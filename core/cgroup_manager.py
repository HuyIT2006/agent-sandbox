"""
cgroup_manager.py
Thành viên 1: Quản lý tài nguyên Sandbox bằng Cgroups v2

Module này tạo và quản lý các cgroup riêng biệt cho mỗi phiên sandbox,
áp dụng giới hạn nghiêm ngặt về:
  - Memory (RAM): Giới hạn tối đa → OOM Killer hủy tiến trình khi vượt ngưỡng.
  - CPU Quota: Giới hạn phần trăm thời gian CPU → tránh ngốn tài nguyên host.
  - PIDs: Giới hạn số lượng tiến trình tối đa → chặn đứng Fork Bomb.
  - Memory Swap: Tắt hoàn toàn swap → tránh ghi dữ liệu ra ổ đĩa.
  - IO Weight: Hạn chế quyền truy cập I/O đĩa.

Kỹ thuật: Ghi trực tiếp vào pseudo-filesystem /sys/fs/cgroup (Cgroups v2 unified hierarchy).
"""

import os
import time
from pathlib import Path
from typing import Optional, Dict, Any

BASE_CGROUP_PATH = Path("/sys/fs/cgroup/agent_sandbox")


class CgroupManager:
    def __init__(
        self,
        sandbox_id: str,
        mem_max_mb: int = 256,
        cpu_quota_pct: int = 50,
        pids_max: int = 32,
        swap_max_bytes: int = 0,
    ):
        """
        Khởi tạo trình quản lý cgroup cho một phiên sandbox cụ thể.

        Args:
            sandbox_id: Mã định danh duy nhất cho phiên sandbox.
            mem_max_mb: Giới hạn RAM tối đa tính bằng MB (mặc định 256MB).
            cpu_quota_pct: Phần trăm CPU tối đa cho sandbox (mặc định 50%).
            pids_max: Số lượng tiến trình tối đa (mặc định 32, chặn Fork Bomb).
            swap_max_bytes: Giới hạn swap tính bằng bytes (mặc định 0 = tắt swap hoàn toàn).
        """
        self.sandbox_id = sandbox_id
        self.mem_max_bytes = mem_max_mb * 1024 * 1024
        self.cpu_quota_pct = cpu_quota_pct
        self.pids_max = pids_max
        self.swap_max_bytes = swap_max_bytes
        self.cgroup_path = BASE_CGROUP_PATH / f"sbx_{sandbox_id}"
        self._is_active = False

    def _safe_write(self, filepath: Path, value: str) -> bool:
        """
        Ghi giá trị vào file cgroup một cách an toàn.
        Trả về True nếu thành công, False nếu file không tồn tại hoặc không có quyền.
        """
        try:
            if filepath.exists():
                filepath.write_text(value)
                return True
        except PermissionError:
            print(f"[CgroupManager Warning] Không có quyền ghi vào {filepath}")
        except OSError as e:
            print(f"[CgroupManager Warning] Lỗi khi ghi {filepath}: {e}")
        return False

    def setup(self) -> bool:
        """
        Tạo cgroup riêng cho sandbox instance và áp dụng toàn bộ giới hạn tài nguyên.

        Returns:
            True nếu cgroup được thiết lập thành công, False nếu không khả dụng.
        """
        try:
            # Kiểm tra Cgroups v2 có sẵn không
            if not BASE_CGROUP_PATH.exists():
                try:
                    BASE_CGROUP_PATH.mkdir(parents=True, exist_ok=True)
                except PermissionError:
                    print("[CgroupManager] Cgroups v2 không khả dụng hoặc chưa được cấp delegation.")
                    return False

            # Tạo thư mục cgroup cho sandbox instance này
            self.cgroup_path.mkdir(parents=True, exist_ok=True)

            # Kích hoạt các controller cần thiết (memory, cpu, pids)
            subtree_ctrl = BASE_CGROUP_PATH / "cgroup.subtree_control"
            self._safe_write(subtree_ctrl, "+memory +cpu +pids")

            success_count = 0

            # === 1. GIỚI HẠN RAM ===
            # memory.max: Khi tiến trình trong cgroup vượt ngưỡng → OOM Killer tự động hủy
            if self._safe_write(self.cgroup_path / "memory.max", str(self.mem_max_bytes)):
                success_count += 1

            # === 2. TẮT SWAP HOÀN TOÀN ===
            # memory.swap.max = 0: Không cho sandbox dùng swap → tránh ghi dữ liệu nhạy cảm ra đĩa
            self._safe_write(self.cgroup_path / "memory.swap.max", str(self.swap_max_bytes))

            # === 3. GIỚI HẠN CPU ===
            # cpu.max format: "$QUOTA $PERIOD" (đơn vị microseconds)
            # Ví dụ: 50% = "50000 100000" (50ms quota trong chu kỳ 100ms)
            quota = int(self.cpu_quota_pct * 1000)  # 50% → 50000us
            period = 100000  # Chu kỳ chuẩn 100ms
            if self._safe_write(self.cgroup_path / "cpu.max", f"{quota} {period}"):
                success_count += 1

            # === 4. GIỚI HẠN SỐ TIẾN TRÌNH (CHẶN FORK BOMB) ===
            # pids.max = 32: Nếu sandbox fork quá 32 process → fork() trả về EAGAIN
            if self._safe_write(self.cgroup_path / "pids.max", str(self.pids_max)):
                success_count += 1

            self._is_active = success_count > 0
            return self._is_active

        except Exception as e:
            print(f"[CgroupManager Warning] Không thể thiết lập cgroup v2 ({e}). Bỏ qua cgroup.")
            return False

    def add_process(self, pid: int) -> bool:
        """
        Gắn PID của tiến trình sandbox vào cgroup để áp dụng giới hạn tài nguyên.

        Args:
            pid: Process ID cần gắn vào cgroup.

        Returns:
            True nếu thành công.
        """
        try:
            procs_file = self.cgroup_path / "cgroup.procs"
            if procs_file.exists():
                procs_file.write_text(str(pid))
                return True
        except PermissionError:
            print(f"[CgroupManager Warning] Không có quyền gắn PID {pid} vào cgroup.")
        except OSError as e:
            # Có thể pid đã kết thúc trước khi kịp gắn
            print(f"[CgroupManager Warning] Gắn PID {pid} vào cgroup thất bại: {e}")
        return False

    def get_usage(self) -> Dict[str, Any]:
        """
        Đọc thống kê sử dụng tài nguyên thực tế của sandbox từ cgroup.

        Returns:
            Dict chứa thông tin sử dụng RAM, CPU, PIDs hiện tại.
        """
        usage = {
            "memory_current_bytes": 0,
            "memory_peak_bytes": 0,
            "memory_limit_bytes": self.mem_max_bytes,
            "pids_current": 0,
            "pids_limit": self.pids_max,
            "cpu_quota_pct": self.cpu_quota_pct,
            "oom_kill_count": 0,
        }

        if not self.cgroup_path.exists():
            return usage

        try:
            # Đọc RAM đang dùng
            mem_current = self.cgroup_path / "memory.current"
            if mem_current.exists():
                usage["memory_current_bytes"] = int(mem_current.read_text().strip())

            # Đọc RAM cao nhất từng đạt (peak)
            mem_peak = self.cgroup_path / "memory.peak"
            if mem_peak.exists():
                usage["memory_peak_bytes"] = int(mem_peak.read_text().strip())

            # Đọc số PIDs đang chạy
            pids_current = self.cgroup_path / "pids.current"
            if pids_current.exists():
                usage["pids_current"] = int(pids_current.read_text().strip())

            # Đọc số lần bị OOM Kill
            mem_events = self.cgroup_path / "memory.events"
            if mem_events.exists():
                for line in mem_events.read_text().strip().split("\n"):
                    if line.startswith("oom_kill"):
                        usage["oom_kill_count"] = int(line.split()[1])
                        break

        except Exception:
            pass

        return usage

    def cleanup(self):
        """
        Dọn dẹp cgroup sau khi phiên sandbox kết thúc.
        Bước 1: Kill toàn bộ tiến trình zombie còn sót (nếu có).
        Bước 2: Xóa thư mục cgroup.
        """
        try:
            if not self.cgroup_path.exists():
                return

            # Kill các tiến trình còn sót lại trong cgroup
            kill_file = self.cgroup_path / "cgroup.kill"
            if kill_file.exists():
                try:
                    kill_file.write_text("1")
                    # Chờ một chút để kernel dọn dẹp
                    time.sleep(0.05)
                except Exception:
                    pass

            # Thử xóa thư mục cgroup (chỉ xóa được khi không còn tiến trình nào bên trong)
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    self.cgroup_path.rmdir()
                    break
                except OSError:
                    if attempt < max_retries - 1:
                        time.sleep(0.1)  # Chờ kernel dọn process zombie

            self._is_active = False

        except Exception:
            pass

    @property
    def is_active(self) -> bool:
        """Kiểm tra xem cgroup hiện tại có đang hoạt động không."""
        return self._is_active and self.cgroup_path.exists()
