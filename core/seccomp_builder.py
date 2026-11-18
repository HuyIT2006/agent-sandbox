"""
seccomp_builder.py
Thành viên 1: Trình biên dịch Seccomp-BPF Filter cho Bubblewrap Sandbox

Module này chuyển đổi danh sách tên syscall bị cấm thành chương trình BPF nhị phân
(Binary Seccomp Filter) tương thích với lệnh bwrap --seccomp <fd>.

Kỹ thuật: Xây dựng chương trình BPF (Berkeley Packet Filter) trực tiếp bằng struct
theo chuẩn của Linux Kernel (linux/seccomp.h, linux/filter.h).

Cấu trúc dữ liệu đầu vào mà kernel cung cấp cho chương trình BPF (seccomp mode):
  struct seccomp_data {
      int   nr;                    // Offset 0: Số hiệu syscall
      __u32 arch;                  // Offset 4: Architecture (AUDIT_ARCH_*)
      __u64 instruction_pointer;   // Offset 8: Instruction pointer
      __u64 args[6];               // Offset 16: Tham số syscall
  };

Mỗi lệnh BPF là 1 struct sock_filter (8 bytes):
  struct sock_filter {
      __u16 code;   // Mã lệnh
      __u8  jt;     // Nhảy tới nếu điều kiện đúng (true)
      __u8  jf;     // Nhảy tới nếu điều kiện sai (false)
      __u32 k;      // Hằng số (giá trị so sánh hoặc offset)
  };

Lưu ý quan trọng: bwrap KHÔNG cần struct sock_fprog header.
Nó chỉ đọc mảng raw sock_filter[] rồi tự tính len = data_size / 8.

Tham khảo:
  - https://man7.org/linux/man-pages/man2/seccomp.2.html
  - https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
  - Flatpak source code (cùng kỹ thuật tạo BPF runtime cho bwrap)
"""

import struct
import os
import json
from pathlib import Path
from typing import List, Dict, Optional

# ============================================================
# 1. BẢNG ÁNH XẠ TÊN SYSCALL -> SỐ HIỆU (x86_64 Linux)
# Nguồn: /usr/include/asm/unistd_64.h (Linux Kernel headers)
# Xác minh bằng: grep __NR_<name> /usr/include/asm/unistd_64.h
# ============================================================
SYSCALL_TABLE_X86_64: Dict[str, int] = {
    # --- Nhóm 1: Debug & Trace ---
    # Cho phép gắn debugger, đọc/ghi bộ nhớ tiến trình khác → container escape
    "ptrace":             101,
    "process_vm_readv":   310,
    "process_vm_writev":  311,

    # --- Nhóm 2: Kernel Module & Boot ---
    # Nạp module kernel = chạy mã tùy ý trong ring 0 (kernel space)
    "init_module":        175,
    "finit_module":       313,
    "delete_module":      176,
    "reboot":             169,
    "kexec_load":         246,
    "kexec_file_load":    320,

    # --- Nhóm 3: Mount & Filesystem ---
    # Gắn/tháo filesystem, thay đổi root → phá vỡ isolation
    "mount":              165,
    "umount2":            166,
    "pivot_root":         155,
    "chroot":             161,
    "swapon":             167,
    "swapoff":            168,

    # --- Nhóm 4: Namespace & Isolation Escape ---
    # Chuyển sang namespace khác hoặc tạo namespace mới → vượt rào sandbox
    "setns":              308,
    "unshare":            272,

    # --- Nhóm 5: eBPF & Performance Monitoring ---
    # Nạp chương trình eBPF hoặc mở performance counter → side-channel attack
    "bpf":                321,
    "perf_event_open":    298,
    "userfaultfd":        323,

    # --- Nhóm 6: Kernel Keyring ---
    # Truy cập khóa bảo mật kernel (TPM, disk encryption keys,...)
    "keyctl":             250,
    "request_key":        249,
    "add_key":            248,

    # --- Nhóm 7: Process Accounting & Misc ---
    "acct":               163,

    # --- Nhóm 8: Clock & Time Manipulation ---
    # Thay đổi đồng hồ hệ thống → phá vỡ TTL, timeout, audit timestamp
    "clock_settime":      227,
    "settimeofday":       164,
    "adjtimex":           159,
    "clock_adjtime":      305,

    # --- Nhóm 9: ABI / Personality ---
    # Đổi execution domain → chạy binary 32-bit để bypass seccomp x86_64 filter
    "personality":        135,
}

# ============================================================
# 2. HẰNG SỐ BPF (Linux Kernel ABI)
# ============================================================

# BPF instruction classes
BPF_LD  = 0x00
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_ALU = 0x04

# BPF ld/ldx size
BPF_W   = 0x00   # Word (32-bit)

# BPF ld/ldx mode
BPF_ABS = 0x20   # Absolute offset vào seccomp_data

# BPF alu/jmp fields
BPF_JEQ  = 0x10  # Jump if Equal
BPF_JSET = 0x40  # Jump if bitwise AND != 0
BPF_K    = 0x00  # Hằng số
BPF_AND  = 0x50  # Bitwise AND

# Seccomp return values
SECCOMP_RET_ALLOW        = 0x7FFF0000  # Cho phép syscall
SECCOMP_RET_KILL_PROCESS = 0x80000000  # Hủy toàn bộ process + threads
SECCOMP_RET_ERRNO        = 0x00050000  # Trả về lỗi (OR với errno)
SECCOMP_RET_LOG          = 0x7FFC0000  # Cho phép nhưng ghi log

# Errno values
EPERM = 1   # Operation not permitted

# Architecture audit values (từ linux/audit.h)
AUDIT_ARCH_X86_64 = 0xC000003E  # EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE

# x32 ABI syscall bit (dùng để chặn x32 bypass attack)
X32_SYSCALL_BIT = 0x40000000

# Offsets trong struct seccomp_data
OFFSET_NR   = 0   # offsetof(struct seccomp_data, nr)
OFFSET_ARCH = 4   # offsetof(struct seccomp_data, arch)


def _bpf_stmt(code: int, k: int) -> bytes:
    """Tạo một BPF statement (không nhảy): struct sock_filter { code, jt=0, jf=0, k }"""
    return struct.pack("HBBI", code, 0, 0, k)


def _bpf_jump(code: int, k: int, jt: int, jf: int) -> bytes:
    """Tạo một BPF jump instruction: struct sock_filter { code, jt, jf, k }"""
    return struct.pack("HBBI", code, jt, jf, k)


class SeccompFilterBuilder:
    """
    Xây dựng chương trình BPF nhị phân (Seccomp Filter) từ danh sách syscall bị cấm.

    Chiến lược bảo mật (Defense-in-Depth trong cùng 1 filter):
    1. Chặn architecture khác x86_64 → KILL (ngăn chạy binary 32-bit bypass)
    2. Chặn x32 ABI syscall bit → KILL (ngăn x32 ABI bypass)
    3. Chặn các syscall nguy hiểm → ERRNO(EPERM) (trả lỗi thay vì kill,
       cho phép ứng dụng xử lý graceful)
    4. Cho phép tất cả syscall còn lại → ALLOW
    """

    def __init__(self, profile_path: Optional[str] = None):
        self.profile_path = profile_path or str(
            Path(__file__).parent / "seccomp" / "seccomp_profile.json"
        )
        self.blocked_syscalls: List[str] = []
        self._load_profile()

    def _load_profile(self):
        """Đọc danh sách syscall bị cấm từ file JSON profile."""
        profile_file = Path(self.profile_path)
        if profile_file.exists():
            with open(profile_file, "r") as f:
                data = json.load(f)
            raw = data.get("blocked_syscalls", [])
            # Hỗ trợ 2 format: mảng string ["ptrace", ...] hoặc mảng object [{"name": "ptrace"}, ...]
            self.blocked_syscalls = []
            for entry in raw:
                if isinstance(entry, str):
                    self.blocked_syscalls.append(entry)
                elif isinstance(entry, dict) and "name" in entry:
                    self.blocked_syscalls.append(entry["name"])
        else:
            # Fallback: danh sách mặc định tối thiểu
            self.blocked_syscalls = [
                "ptrace", "bpf", "mount", "umount2", "chroot",
                "reboot", "kexec_load", "kexec_file_load",
                "pivot_root", "setns", "unshare",
                "init_module", "finit_module", "delete_module",
                "swapon", "swapoff",
                "keyctl", "request_key", "add_key",
                "userfaultfd", "perf_event_open",
            ]

    def _resolve_syscall_numbers(self) -> List[int]:
        """Chuyển tên syscall thành số hiệu, bỏ qua tên không nhận diện được."""
        numbers = []
        for name in self.blocked_syscalls:
            # Chuẩn hóa: một số profile dùng "sys_chroot" thay vì "chroot"
            clean_name = name.replace("sys_", "")
            if clean_name in SYSCALL_TABLE_X86_64:
                numbers.append(SYSCALL_TABLE_X86_64[clean_name])
            else:
                print(f"[SeccompBuilder Warning] Syscall '{name}' không có trong bảng x86_64, bỏ qua.")
        return sorted(set(numbers))  # Loại bỏ trùng lặp và sắp xếp

    def build_bpf_program(self) -> bytes:
        """
        Biên dịch chương trình BPF nhị phân hoàn chỉnh.

        Cấu trúc chương trình BPF:
          [0] LD  arch                         ; Load architecture từ seccomp_data
          [1] JEQ AUDIT_ARCH_X86_64 → +1 else → KILL_ARCH
          [2] LD  nr                           ; Load syscall number
          [3] JSET X32_SYSCALL_BIT → KILL_X32  ; Chặn x32 ABI bypass attack
          [4..N] JEQ <syscall_nr> → BLOCK      ; Chặn từng syscall nguy hiểm
          [N+1] RET ALLOW                      ; Cho phép syscall hợp lệ
          [N+2] RET ERRNO(EPERM)               ; Trả lỗi cho syscall bị cấm
          [N+3] RET KILL_PROCESS               ; Hủy khi sai arch hoặc x32 bypass

        Vì sao dùng ERRNO(EPERM) thay vì KILL cho syscall bị cấm?
          → Cho phép ứng dụng bắt lỗi và tiếp tục chạy thay vì bị kill đột ngột.
          → Dễ debug hơn khi phát triển (thấy lỗi "Operation not permitted").
          → Vẫn an toàn vì syscall đã bị chặn, không thực thi được.

        Vì sao dùng KILL_PROCESS cho sai architecture / x32?
          → Đây là hành vi cố ý bypass seccomp filter (tấn công chủ đích),
            không nên cho cơ hội tiếp tục thực thi.
        """
        blocked_nrs = self._resolve_syscall_numbers()

        instructions = []

        # ===== Bước 1: KIỂM TRA ARCHITECTURE =====
        # Load trường arch từ seccomp_data (offset 4)
        instructions.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH))

        # Nếu arch == x86_64 → tiếp tục (jt=0 = lệnh kế tiếp)
        # Nếu arch != x86_64 → nhảy tới KILL_PROCESS (cuối chương trình)
        #   Vị trí KILL = 1 (LD nr) + 1 (JSET x32) + len(blocked) + 1 (ALLOW) + 1 (ERRNO)
        kill_offset = len(blocked_nrs) + 4
        instructions.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, kill_offset))

        # ===== Bước 2: LOAD SYSCALL NUMBER =====
        instructions.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR))

        # ===== Bước 3: CHẶN x32 ABI BYPASS =====
        # Trên x86_64, syscall x32 có bit 0x40000000 bật trong nr.
        # Nếu bit này bật → đây là x32 ABI call → KILL (nhảy tới cuối)
        x32_kill_offset = len(blocked_nrs) + 2  # +1 ALLOW + 1 ERRNO → tới KILL
        instructions.append(_bpf_jump(BPF_JMP | BPF_JSET | BPF_K, X32_SYSCALL_BIT, x32_kill_offset, 0))

        # ===== Bước 4: SO SÁNH TỪNG SYSCALL BỊ CẤM =====
        for i, nr in enumerate(blocked_nrs):
            remaining = len(blocked_nrs) - i - 1
            # Nếu nr trùng → nhảy qua các JEQ còn lại + RET ALLOW → tới RET ERRNO
            jt = remaining + 1
            instructions.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, jt, 0))

        # ===== Bước 5: ALLOW - Không vi phạm =====
        instructions.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

        # ===== Bước 6: ERRNO - Syscall bị cấm → trả lỗi EPERM =====
        instructions.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM))

        # ===== Bước 7: KILL - Architecture sai hoặc x32 bypass → hủy process =====
        instructions.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))

        program = b"".join(instructions)

        # Validate: kích thước phải là bội số của 8 (mỗi sock_filter = 8 bytes)
        assert len(program) % 8 == 0, \
            f"BPF program size ({len(program)}) không phải bội số của 8!"

        return program

    def write_to_fd(self) -> int:
        """
        Biên dịch filter BPF và ghi vào một pipe file descriptor.
        Trả về fd số (int) để truyền cho bwrap --seccomp <fd>.

        Quy trình:
        1. Tạo pipe() → (read_fd, write_fd)
        2. Ghi raw sock_filter[] bytes vào write_fd
        3. Đóng write_fd → bwrap đọc đến EOF
        4. Đánh dấu read_fd là inheritable → bwrap kế thừa fd
        5. Trả về read_fd

        Lưu ý: Cần truyền pass_fds=(fd,) khi subprocess.Popen() để
        Python không tự đóng fd trước khi exec bwrap.
        """
        bpf_program = self.build_bpf_program()

        # Tạo pipe: read_fd để bwrap đọc, write_fd để ta ghi
        read_fd, write_fd = os.pipe()

        # Ghi chương trình BPF vào pipe
        os.write(write_fd, bpf_program)
        os.close(write_fd)  # Đóng đầu ghi → bwrap đọc tới EOF

        # Đánh dấu read_fd là inheritable (bwrap cần kế thừa fd này)
        os.set_inheritable(read_fd, True)

        return read_fd

    def get_blocked_count(self) -> int:
        """Trả về số lượng syscall thực tế bị chặn (đã resolve thành công)."""
        return len(self._resolve_syscall_numbers())

    def get_info(self) -> Dict:
        """Trả về thông tin chi tiết về bộ lọc Seccomp hiện tại."""
        resolved = self._resolve_syscall_numbers()
        # 5 lệnh cơ bản + len(resolved) lệnh so sánh
        total_instructions = len(resolved) + 5  # arch_check(2) + LD_nr + JSET_x32 + JEQs + ALLOW + ERRNO + KILL
        total_instructions = 4 + len(resolved) + 3  # Chính xác hơn
        return {
            "total_rules_in_profile": len(self.blocked_syscalls),
            "total_resolved_on_x86_64": len(resolved),
            "blocked_syscall_names": self.blocked_syscalls,
            "blocked_syscall_numbers": resolved,
            "bpf_instruction_count": total_instructions,
            "bpf_program_size_bytes": total_instructions * 8,
        }


if __name__ == "__main__":
    builder = SeccompFilterBuilder()
    info = builder.get_info()
    print("=" * 60)
    print("  SECCOMP-BPF FILTER BUILDER - Thông tin bộ lọc")
    print("=" * 60)
    print(f"  Số syscall bị chặn (profile) : {info['total_rules_in_profile']}")
    print(f"  Số syscall resolve thành công : {info['total_resolved_on_x86_64']}")
    print(f"  Kích thước chương trình BPF   : {info['bpf_program_size_bytes']} bytes")
    print(f"  Số lệnh BPF                  : {info['bpf_instruction_count']}")
    print()
    print("  Danh sách syscall bị chặn:")
    for name in info['blocked_syscall_names']:
        clean = name.replace("sys_", "")
        nr = SYSCALL_TABLE_X86_64.get(clean, "?")
        print(f"    - {name:<25} (nr={nr})")
    print()

    # Test: Tạo BPF program và kiểm tra kích thước
    program = builder.build_bpf_program()
    print(f"  [Test] BPF Program generated: {len(program)} bytes, "
          f"{len(program) // 8} instructions")
    assert len(program) % 8 == 0, "INVALID: size not multiple of 8!"
    print(f"  [Test] Size validation: PASS")

    # Test: Tạo file descriptor
    fd = builder.write_to_fd()
    print(f"  [Test] Seccomp FD created: fd={fd}")
    os.close(fd)
    print(f"  [Test] FD cleanup: PASS")
    print("=" * 60)
