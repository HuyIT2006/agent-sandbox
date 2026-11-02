"""
runner.py
Thành viên 1: Core Sandbox Execution Engine dựa trên Bubblewrap (bwrap)
Cung cấp khả năng cô lập tiến trình bằng Linux Namespaces và Filesystem Isolation.
"""

import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, Any, Optional

from core.cgroup_manager import CgroupManager


class SandboxRunner:
    def __init__(
        self,
        rootfs_path: Optional[str] = None,
        mem_limit_mb: int = 256,
        cpu_quota_pct: int = 50,
        pids_max: int = 32,
        default_timeout: int = 20,
    ):
        self.rootfs_path = Path(rootfs_path) if rootfs_path else Path(__file__).parent.parent / "rootfs/alpine"
        self.mem_limit_mb = mem_limit_mb
        self.cpu_quota_pct = cpu_quota_pct
        self.pids_max = pids_max
        self.default_timeout = default_timeout
        self._check_bwrap()

    def _check_bwrap(self):
        if not shutil.which("bwrap"):
            raise RuntimeError("Lỗi: 'bwrap' (Bubblewrap) chưa được cài đặt trên hệ thống!")

    def execute(
        self,
        command: str,
        workspace_dir: Optional[str] = None,
        network_enabled: bool = False,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Thực thi lệnh trong môi trường cô lập Bubblewrap.
        """
        sandbox_id = str(uuid.uuid4())[:8]
        timeout_sec = timeout or self.default_timeout
        ephemeral_ws = False

        if not workspace_dir:
            workspace_path = Path(f"/tmp/agent_sbx_{sandbox_id}")
            workspace_path.mkdir(parents=True, exist_ok=True)
            ephemeral_ws = True
        else:
            workspace_path = Path(workspace_dir)
            workspace_path.mkdir(parents=True, exist_ok=True)

        cgroup = CgroupManager(
            sandbox_id=sandbox_id,
            mem_max_mb=self.mem_limit_mb,
            cpu_quota_pct=self.cpu_quota_pct,
            pids_max=self.pids_max,
        )
        cgroup.setup()

        # Build Bubblewrap command
        bwrap_cmd = [
            "bwrap",
            # Namespaces isolation
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup",
        ]

        # Network isolation: Mặc định unshare net (Offline mode)
        if not network_enabled:
            bwrap_cmd.append("--unshare-net")

        # Rootfs isolation:
        # Nếu có Alpine rootfs -> ro-bind. Nếu chưa tải -> ro-bind hệ thống host nhưng bảo vệ
        if self.rootfs_path.exists() and (self.rootfs_path / "bin/sh").exists():
            bwrap_cmd.extend([
                "--ro-bind", str(self.rootfs_path), "/",
                "--tmpfs", "/tmp",
                "--proc", "/proc",
                "--dev", "/dev",
                "--bind", str(workspace_path), "/workspace",
                "--chdir", "/workspace",
            ])
            shell_exec = ["/bin/sh", "-c", command]
        else:
            # Fallback an toàn với hệ thống host hiện tại: Read-only toàn bộ host system
            bwrap_cmd.extend([
                "--ro-bind", "/usr", "/usr",
                "--ro-bind", "/lib", "/lib",
                "--ro-bind", "/lib64", "/lib64",
                "--ro-bind", "/bin", "/bin",
                "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf",
                "--tmpfs", "/tmp",
                "--proc", "/proc",
                "--dev", "/dev",
                "--bind", str(workspace_path), "/workspace",
                "--chdir", "/workspace",
            ])
            shell_exec = ["/bin/bash", "-c", command]

        # Tự động hủy process khi parent thoát
        bwrap_cmd.append("--die-with-parent")
        bwrap_cmd.extend(shell_exec)

        start_time = time.time()
        try:
            proc = subprocess.Popen(
                bwrap_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid,
            )

            # Đăng ký PID vào cgroup
            cgroup.add_process(proc.pid)

            try:
                stdout, stderr = proc.communicate(timeout=timeout_sec)
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                # Triệt tiêu toàn bộ process group nếu quá timeout
                import signal
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                stdout, stderr = proc.communicate()
                exit_code = 124  # Standard timeout exit code
                stderr = (stderr or "") + f"\n[Security Alert] Lệnh bị hủy do vượt quá giới hạn thời gian ({timeout_sec}s)!"

        except Exception as e:
            stdout = ""
            stderr = f"[Runner Error]: {str(e)}"
            exit_code = 1
        finally:
            duration_ms = int((time.time() - start_time) * 1000)
            cgroup.cleanup()
            if ephemeral_ws and workspace_path.exists():
                shutil.rmtree(workspace_path, ignore_errors=True)

        return {
            "sandbox_id": sandbox_id,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "timed_out": exit_code == 124,
        }


if __name__ == "__main__":
    runner = SandboxRunner()
    print("[*] Kiểm thử chạy lệnh 'uname -a && id' trong Sandbox:")
    res = runner.execute("uname -a && id")
    print("Stdout:", res["stdout"])
    print("Stderr:", res["stderr"])
    print("Exit Code:", res["exit_code"])
    print("Duration:", res["duration_ms"], "ms")
