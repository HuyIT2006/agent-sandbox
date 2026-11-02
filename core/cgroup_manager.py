"""
cgroup_manager.py
Thành viên 1: Quản lý tài nguyên Sandbox bằng Cgroups v2
Giới hạn: Memory (RAM), CPU Quota, PIDs (chống Fork Bomb)
"""

import os
from pathlib import Path
from typing import Optional

BASE_CGROUP_PATH = Path("/sys/fs/cgroup/agent_sandbox")


class CgroupManager:
    def __init__(self, sandbox_id: str, mem_max_mb: int = 256, cpu_quota_pct: int = 50, pids_max: int = 32):
        self.sandbox_id = sandbox_id
        self.mem_max_bytes = mem_max_mb * 1024 * 1024
        self.cpu_quota_pct = cpu_quota_pct  # 50% = 50000 100000
        self.pids_max = pids_max
        self.cgroup_path = BASE_CGROUP_PATH / f"sbx_{sandbox_id}"

    def setup(self) -> bool:
        """Tạo cgroup riêng cho sandbox instance và ghi giới hạn tài nguyên."""
        try:
            if not BASE_CGROUP_PATH.exists():
                # Fallback nếu chưa tạo delegation
                return False

            self.cgroup_path.mkdir(parents=True, exist_ok=True)

            # 1. Giới hạn RAM (OOM Killer sẽ xử lý process trong sandbox nếu vượt)
            mem_file = self.cgroup_path / "memory.max"
            if mem_file.exists():
                mem_file.write_text(str(self.mem_max_bytes))

            # 2. Giới hạn CPU (Ví dụ: 50% core = 50000 trong chu kỳ 100000us)
            cpu_file = self.cgroup_path / "cpu.max"
            if cpu_file.exists():
                quota = int(self.cpu_quota_pct * 1000)
                cpu_file.write_text(f"{quota} 100000")

            # 3. Giới hạn số lượng tiến trình (Chống Fork Bomb hoàn toàn)
            pids_file = self.cgroup_path / "pids.max"
            if pids_file.exists():
                pids_file.write_text(str(self.pids_max))

            return True
        except Exception as e:
            print(f"[Warning] Không thể thiết lập cgroup v2 ({e}). Bỏ qua cgroup.")
            return False

    def add_process(self, pid: int) -> bool:
        """Gắn PID của sandbox vào cgroup."""
        try:
            procs_file = self.cgroup_path / "cgroup.procs"
            if procs_file.exists():
                procs_file.write_text(str(pid))
                return True
        except Exception as e:
            print(f"[Warning] Gắn PID {pid} vào cgroup thất bại: {e}")
        return False

    def cleanup(self):
        """Xóa cgroup sau khi tiến trình sandbox kết thúc."""
        try:
            if self.cgroup_path.exists():
                # Kill any remaining zombie processes if any
                kill_file = self.cgroup_path / "cgroup.kill"
                if kill_file.exists():
                    try:
                        kill_file.write_text("1")
                    except Exception:
                        pass
                self.cgroup_path.rmdir()
        except Exception:
            pass
