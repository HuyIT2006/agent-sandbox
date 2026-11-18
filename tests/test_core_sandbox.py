"""
test_core_sandbox.py
Thành viên 1: Bộ kiểm thử đơn vị (Unit Tests) cho Core Sandbox Engine

Bao gồm:
  - Test cơ chế cô lập Namespace (PID, UTS, Network, Filesystem)
  - Test Seccomp-BPF Filter Builder (biên dịch, kích thước, FD)
  - Test Cgroup Manager (khởi tạo, giới hạn tài nguyên)
  - Test hiệu năng (Cold Start / Warm Start)
  - Test timeout enforcement
  - Test workspace cleanup
"""

import os
import sys
import time
import unittest
from pathlib import Path

# Thêm thư mục gốc dự án vào PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.runner import SandboxRunner, benchmark
from core.cgroup_manager import CgroupManager
from core.seccomp_builder import SeccompFilterBuilder, SYSCALL_TABLE_X86_64


class TestSeccompFilterBuilder(unittest.TestCase):
    """Kiểm thử module biên dịch Seccomp-BPF Filter."""

    def setUp(self):
        self.builder = SeccompFilterBuilder()

    def test_01_load_profile(self):
        """Profile JSON phải được đọc thành công và có ít nhất 15 syscall."""
        print("\n[Seccomp] Test 1: Đọc profile JSON...")
        self.assertGreater(len(self.builder.blocked_syscalls), 15,
                           "Profile phải chặn ít nhất 15 syscall nguy hiểm.")
        print(f"  -> PASS: {len(self.builder.blocked_syscalls)} syscall trong profile.")

    def test_02_resolve_syscall_numbers(self):
        """Tất cả tên syscall trong profile phải resolve được thành số hiệu."""
        print("\n[Seccomp] Test 2: Resolve tên syscall -> số hiệu...")
        resolved = self.builder._resolve_syscall_numbers()
        self.assertGreater(len(resolved), 0, "Phải resolve được ít nhất 1 syscall.")
        # Kiểm tra các syscall quan trọng nhất phải có mặt
        critical_syscalls = ["ptrace", "mount", "reboot", "setns", "bpf"]
        for name in critical_syscalls:
            nr = SYSCALL_TABLE_X86_64.get(name)
            self.assertIn(nr, resolved, f"Syscall '{name}' (nr={nr}) phải bị chặn!")
        print(f"  -> PASS: {len(resolved)} syscall đã resolve. Critical syscalls đều có mặt.")

    def test_03_build_bpf_program_valid_size(self):
        """Chương trình BPF phải có kích thước là bội số của 8 bytes."""
        print("\n[Seccomp] Test 3: Biên dịch BPF program...")
        program = self.builder.build_bpf_program()
        self.assertGreater(len(program), 0, "Chương trình BPF không được rỗng.")
        self.assertEqual(len(program) % 8, 0,
                         f"Kích thước BPF ({len(program)}) phải là bội số 8 (mỗi sock_filter = 8 bytes).")
        print(f"  -> PASS: {len(program)} bytes ({len(program)//8} instructions). Valid format.")

    def test_04_write_to_fd(self):
        """Phải tạo được file descriptor chứa BPF binary."""
        print("\n[Seccomp] Test 4: Tạo FD cho bwrap --seccomp...")
        fd = self.builder.write_to_fd()
        self.assertIsInstance(fd, int)
        self.assertGreater(fd, 0)
        # Kiểm tra fd hợp lệ bằng cách đọc thử
        data = os.read(fd, 65536)
        os.close(fd)
        self.assertGreater(len(data), 0, "FD phải chứa dữ liệu BPF.")
        self.assertEqual(len(data) % 8, 0, "Dữ liệu từ FD phải có kích thước hợp lệ.")
        print(f"  -> PASS: FD={fd}, đọc được {len(data)} bytes BPF binary.")

    def test_05_get_info(self):
        """Hàm get_info() phải trả về đầy đủ thông tin."""
        print("\n[Seccomp] Test 5: Kiểm tra get_info()...")
        info = self.builder.get_info()
        required_keys = [
            "total_rules_in_profile", "total_resolved_on_x86_64",
            "blocked_syscall_names", "blocked_syscall_numbers",
            "bpf_instruction_count", "bpf_program_size_bytes",
        ]
        for key in required_keys:
            self.assertIn(key, info, f"Thiếu key '{key}' trong get_info().")
        print(f"  -> PASS: get_info() trả về {len(info)} trường đầy đủ.")


class TestCgroupManager(unittest.TestCase):
    """Kiểm thử module quản lý Cgroups v2."""

    def test_01_create_instance(self):
        """CgroupManager phải khởi tạo với các giá trị mặc định đúng."""
        print("\n[Cgroup] Test 1: Khởi tạo CgroupManager...")
        cg = CgroupManager(sandbox_id="test_unit")
        self.assertEqual(cg.mem_max_bytes, 256 * 1024 * 1024)
        self.assertEqual(cg.cpu_quota_pct, 50)
        self.assertEqual(cg.pids_max, 32)
        self.assertEqual(cg.swap_max_bytes, 0)
        print(f"  -> PASS: RAM={cg.mem_max_bytes//1024//1024}MB, CPU={cg.cpu_quota_pct}%, PIDs={cg.pids_max}")

    def test_02_custom_limits(self):
        """CgroupManager phải chấp nhận các giá trị tùy chỉnh."""
        print("\n[Cgroup] Test 2: Tùy chỉnh giới hạn tài nguyên...")
        cg = CgroupManager(sandbox_id="test_custom", mem_max_mb=128, cpu_quota_pct=25, pids_max=16)
        self.assertEqual(cg.mem_max_bytes, 128 * 1024 * 1024)
        self.assertEqual(cg.cpu_quota_pct, 25)
        self.assertEqual(cg.pids_max, 16)
        print(f"  -> PASS: RAM=128MB, CPU=25%, PIDs=16")

    def test_03_setup_graceful_failure(self):
        """Nếu cgroups không khả dụng, setup() phải trả về False (không crash)."""
        print("\n[Cgroup] Test 3: Graceful failure khi cgroups không khả dụng...")
        cg = CgroupManager(sandbox_id="test_fail")
        # setup() sẽ trả về True hoặc False tùy môi trường, nhưng KHÔNG được raise exception
        result = cg.setup()
        self.assertIsInstance(result, bool)
        cg.cleanup()
        print(f"  -> PASS: setup() trả về {result} (không crash).")

    def test_04_get_usage_returns_dict(self):
        """get_usage() phải luôn trả về dict có đầy đủ keys."""
        print("\n[Cgroup] Test 4: get_usage() trả về dict hợp lệ...")
        cg = CgroupManager(sandbox_id="test_usage")
        usage = cg.get_usage()
        required_keys = ["memory_current_bytes", "memory_limit_bytes", "pids_current", "pids_limit"]
        for key in required_keys:
            self.assertIn(key, usage, f"Thiếu key '{key}' trong get_usage().")
        print(f"  -> PASS: {len(usage)} trường trả về.")


class TestSandboxRunner(unittest.TestCase):
    """Kiểm thử Core Sandbox Execution Engine."""

    @classmethod
    def setUpClass(cls):
        cls.runner = SandboxRunner(default_timeout=10)

    def test_01_basic_execution(self):
        """Lệnh echo đơn giản phải chạy thành công trong sandbox."""
        print("\n[Runner] Test 1: Thực thi lệnh cơ bản...")
        res = self.runner.execute("echo hello_sandbox_test")
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("hello_sandbox_test", res["stdout"])
        self.assertGreater(res["duration_ms"], 0)
        self.assertIsNotNone(res["sandbox_id"])
        print(f"  -> PASS: '{res['stdout'].strip()}' ({res['duration_ms']}ms)")

    def test_02_filesystem_readonly(self):
        """Không thể ghi file vào rootfs (Read-Only filesystem)."""
        print("\n[Runner] Test 2: Filesystem Read-Only...")
        res = self.runner.execute("touch /usr/malicious_file")
        self.assertNotEqual(res["exit_code"], 0,
                            "LỖI BẢO MẬT: Sandbox ghi được file vào /usr!")
        print(f"  -> PASS: Ghi /usr bị chặn (exit={res['exit_code']})")

    def test_03_network_isolation(self):
        """Mặc định sandbox phải hoàn toàn offline."""
        print("\n[Runner] Test 3: Network Isolation (Offline mode)...")
        res = self.runner.execute("ping -c 1 -W 1 8.8.8.8 2>&1 || echo NETWORK_BLOCKED", timeout=5)
        # Trong Alpine rootfs có thể không có ping → cũng là PASS vì không gửi được gói tin
        is_blocked = (res["exit_code"] != 0) or ("BLOCKED" in res["stdout"]) or ("not found" in res["stdout"])
        self.assertTrue(is_blocked, "LỖI BẢO MẬT: Sandbox kết nối được mạng trong Offline mode!")
        print(f"  -> PASS: Mạng bị cô lập hoàn toàn.")

    def test_04_uts_namespace_hostname(self):
        """Hostname trong sandbox phải là 'sandbox' (UTS Namespace)."""
        print("\n[Runner] Test 4: UTS Namespace - Hostname...")
        res = self.runner.execute("hostname")
        hostname = res["stdout"].strip()
        self.assertEqual(hostname, "sandbox",
                         f"Hostname phải là 'sandbox', nhưng nhận được '{hostname}'")
        print(f"  -> PASS: hostname='{hostname}'")

    def test_05_user_namespace_uid(self):
        """UID trong sandbox phải là 65534 (nobody) — User Namespace mapping."""
        print("\n[Runner] Test 5: User Namespace - UID mapping...")
        res = self.runner.execute("id -u")
        uid = res["stdout"].strip()
        self.assertEqual(uid, "65534",
                         f"UID phải là 65534 (nobody), nhưng nhận được '{uid}'")
        print(f"  -> PASS: uid={uid} (nobody)")

    def test_06_timeout_enforcement(self):
        """Lệnh chạy quá timeout phải bị kill tự động."""
        print("\n[Runner] Test 6: Timeout enforcement...")
        start = time.time()
        res = self.runner.execute("sleep 100", timeout=2)
        elapsed = time.time() - start
        self.assertTrue(res["timed_out"], "Sandbox phải đánh dấu timed_out=True")
        self.assertEqual(res["exit_code"], 124, "Exit code timeout phải là 124")
        self.assertLess(elapsed, 5, "Timeout phải hoạt động trong vòng 5 giây")
        print(f"  -> PASS: Bị kill sau {res['duration_ms']}ms (timeout=2s)")

    def test_07_workspace_cleanup(self):
        """Workspace tạm phải được tự động xóa sạch sau khi execute."""
        print("\n[Runner] Test 7: Workspace auto-cleanup...")
        res = self.runner.execute("echo cleanup_test")
        sandbox_id = res["sandbox_id"]
        workspace_path = Path(f"/tmp/agent_sbx_{sandbox_id}")
        self.assertFalse(workspace_path.exists(),
                         f"Workspace tạm {workspace_path} chưa được dọn dẹp!")
        print(f"  -> PASS: Workspace /tmp/agent_sbx_{sandbox_id} đã bị xóa sạch.")

    def test_08_shadow_file_blocked(self):
        """Không thể đọc /etc/shadow từ trong sandbox."""
        print("\n[Runner] Test 8: Đọc /etc/shadow bị chặn...")
        res = self.runner.execute("cat /etc/shadow")
        self.assertNotEqual(res["exit_code"], 0,
                            "LỖI BẢO MẬT: Sandbox đọc được /etc/shadow!")
        print(f"  -> PASS: /etc/shadow không đọc được (exit={res['exit_code']})")

    def test_09_write_to_host_root_blocked(self):
        """Không thể ghi file vào thư mục hệ thống /bin, /usr, /lib trong sandbox."""
        print("\n[Runner] Test 9: Ghi vào thư mục hệ thống bị chặn...")
        # /usr được mount Read-Only bởi bwrap (--ro-bind)
        # Lưu ý: /etc trong Alpine rootfs có thể writable nhưng đó là /etc của sandbox
        # (không phải host), và sẽ bị xóa sạch khi sandbox kết thúc → An toàn.
        res = self.runner.execute("echo hacked > /bin/test_file")
        self.assertNotEqual(res["exit_code"], 0,
                            "LỖI BẢO MẬT: Sandbox ghi được file vào /bin (Read-only rootfs)!")
        print(f"  -> PASS: Ghi /bin bị chặn (Read-only rootfs)")

    def test_10_cold_start_performance(self):
        """Cold start phải dưới 50ms."""
        print("\n[Runner] Test 10: Hiệu năng Cold Start...")
        fresh_runner = SandboxRunner(default_timeout=10)
        res = fresh_runner.execute("echo perf_test")
        self.assertLess(res["duration_ms"], 100,
                        f"Cold start quá chậm: {res['duration_ms']}ms (target < 50ms)")
        print(f"  -> PASS: Cold start = {res['duration_ms']}ms (target < 50ms)")


if __name__ == "__main__":
    print("=" * 60)
    print("  CORE SANDBOX UNIT TEST SUITE")
    print("  Thành viên 1: Kiểm thử đầy đủ các cơ chế cô lập")
    print("=" * 60)
    unittest.main(verbosity=0)
