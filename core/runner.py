"""
runner.py
Thành viên 1: Core Sandbox Execution Engine dựa trên Bubblewrap (bwrap)

Module này cung cấp lớp SandboxRunner — nhân thực thi trung tâm của hệ thống.
Mỗi lần gọi execute(), module sẽ:
  1. Tạo workspace tạm thời (tmpfs — tự hủy khi kết thúc)
  2. Khởi tạo Cgroups v2 (giới hạn RAM, CPU, PIDs)
  3. Biên dịch Seccomp-BPF filter runtime → ghi vào pipe fd
  4. Khởi chạy tiến trình trong Bubblewrap với đầy đủ Linux Namespace isolation:
     - PID Namespace: Tiến trình sandbox có PID 1, không nhìn thấy tiến trình host
     - Mount Namespace: Rootfs Read-Only (Alpine), workspace ghi vào tmpfs
     - Network Namespace: Mặc định cô lập hoàn toàn (Offline mode)
     - IPC Namespace: Cô lập System V IPC (shared memory, semaphore, message queue)
     - UTS Namespace: Hostname riêng biệt ("sandbox")
     - User Namespace: Ánh xạ UID/GID → nobody (65534) trong sandbox
  5. Thu thập kết quả stdout/stderr, exit code, thời gian thực thi
  6. Dọn dẹp: Xóa workspace, giải phóng cgroup, đóng fd

Yêu cầu hiệu năng:
  - Cold start (khởi tạo mới hoàn toàn): < 50ms
  - Warm start (reuse rootfs đã cache): < 10ms
"""

import os
import shutil
import signal
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, Any, Optional

from core.cgroup_manager import CgroupManager
from core.seccomp_builder import SeccompFilterBuilder


class SandboxRunner:
    """
    Nhân thực thi Sandbox cô lập dựa trên Bubblewrap (bwrap).

    Mỗi instance SandboxRunner có thể tái sử dụng cho nhiều lần execute().
    SeccompFilterBuilder được cache sẵn trong __init__ để tăng tốc warm start.
    """

    def __init__(
        self,
        rootfs_path: Optional[str] = None,
        mem_limit_mb: int = 256,
        cpu_quota_pct: int = 50,
        pids_max: int = 32,
        default_timeout: int = 20,
    ):
        """
        Khởi tạo Sandbox Runner.

        Args:
            rootfs_path: Đường dẫn tới Alpine Mini RootFS (Read-Only).
                         Mặc định: <project>/rootfs/alpine
            mem_limit_mb: Giới hạn RAM tối đa (MB). Mặc định: 256MB.
            cpu_quota_pct: Giới hạn CPU (%). Mặc định: 50%.
            pids_max: Số lượng tiến trình tối đa. Mặc định: 32 (chặn Fork Bomb).
            default_timeout: Thời gian chạy tối đa (giây). Mặc định: 20s.
        """
        self.rootfs_path = Path(rootfs_path) if rootfs_path else Path(__file__).parent.parent / "rootfs/alpine"
        self.mem_limit_mb = mem_limit_mb
        self.cpu_quota_pct = cpu_quota_pct
        self.pids_max = pids_max
        self.default_timeout = default_timeout

        # Cache SeccompFilterBuilder (chỉ đọc profile 1 lần, dùng nhiều lần)
        self._seccomp_builder = SeccompFilterBuilder()

        # Kiểm tra bwrap có sẵn không
        self._check_bwrap()

    def _check_bwrap(self):
        """Kiểm tra xem Bubblewrap (bwrap) đã được cài đặt trên hệ thống chưa."""
        if not shutil.which("bwrap"):
            raise RuntimeError(
                "Lỗi: 'bwrap' (Bubblewrap) chưa được cài đặt!\n"
                "  Ubuntu/Debian: sudo apt install bubblewrap\n"
                "  Fedora/RHEL:   sudo dnf install bubblewrap"
            )

    def _has_alpine_rootfs(self) -> bool:
        """Kiểm tra xem Alpine Mini RootFS đã được tải và giải nén sẵn chưa."""
        return self.rootfs_path.exists() and (self.rootfs_path / "bin" / "sh").exists()

    def _build_bwrap_command(
        self,
        command: str,
        workspace_path: Path,
        network_enabled: bool,
        seccomp_fd: Optional[int],
    ) -> list:
        """
        Xây dựng danh sách tham số cho lệnh bwrap.

        Returns:
            List các tham số bwrap + shell + lệnh cần thực thi.
        """
        bwrap_cmd = ["bwrap"]

        # ============================================================
        # A. LINUX NAMESPACES ISOLATION
        # ============================================================

        # PID Namespace: Tiến trình sandbox có PID riêng (bắt đầu từ 1),
        # không nhìn thấy bất kỳ tiến trình nào trên host.
        bwrap_cmd.append("--unshare-pid")

        # IPC Namespace: Cô lập System V IPC (shared memory, semaphore,
        # message queue) → sandbox không thể giao tiếp với host qua IPC.
        bwrap_cmd.append("--unshare-ipc")

        # UTS Namespace + Custom Hostname: Đặt hostname riêng cho sandbox.
        # Nếu ứng dụng trong sandbox gọi gethostname() sẽ thấy "sandbox"
        # thay vì hostname thật của host.
        bwrap_cmd.extend(["--unshare-uts", "--hostname", "sandbox"])

        # Cgroup Namespace: Sandbox nhìn thấy cgroup hierarchy riêng,
        # không biết đến cgroup cha trên host.
        bwrap_cmd.append("--unshare-cgroup")

        # User Namespace: Ánh xạ UID/GID bên trong sandbox.
        # UID 0 (root) bên ngoài → UID 65534 (nobody) bên trong.
        # Sandbox chạy với quyền nobody, không có quyền root.
        bwrap_cmd.extend([
            "--unshare-user",
            "--uid", "65534",
            "--gid", "65534",
        ])

        # Network Namespace: Mặc định Offline mode (--unshare-net).
        # Khi bật: sandbox vẫn cần qua Egress Firewall của TV 3 mới ra Internet.
        if not network_enabled:
            bwrap_cmd.append("--unshare-net")

        # ============================================================
        # B. FILESYSTEM ISOLATION (ROOTFS + WORKSPACE)
        # ============================================================

        if self._has_alpine_rootfs():
            # Chế độ Alpine RootFS (Production Mode):
            # - Toàn bộ rootfs Alpine được mount Read-Only (--ro-bind)
            # - /tmp dùng tmpfs (RAM disk) → tự hủy khi sandbox kết thúc
            # - /proc mount riêng biệt cho sandbox
            # - /dev cung cấp device nodes tối thiểu (/dev/null, /dev/zero, /dev/urandom)
            # - /workspace gắn thư mục làm việc tạm (read-write)
            bwrap_cmd.extend([
                "--ro-bind", str(self.rootfs_path), "/",
                "--tmpfs", "/tmp",
                "--tmpfs", "/run",
                "--proc", "/proc",
                "--dev", "/dev",
                "--bind", str(workspace_path), "/workspace",
                "--chdir", "/workspace",
            ])
            shell_exec = ["/bin/sh", "-c", command]
        else:
            # Chế độ Fallback (Host Filesystem — Development Mode):
            # Khi chưa tải Alpine rootfs → sử dụng host filesystem nhưng
            # mount Read-Only toàn bộ thư mục hệ thống.
            bwrap_cmd.extend([
                "--ro-bind", "/usr", "/usr",
                "--ro-bind", "/lib", "/lib",
            ])
            # /lib64 có thể không tồn tại trên một số distro
            if Path("/lib64").exists():
                bwrap_cmd.extend(["--ro-bind", "/lib64", "/lib64"])
            bwrap_cmd.extend([
                "--ro-bind", "/bin", "/bin",
                "--ro-bind", "/sbin", "/sbin",
                "--symlink", "/usr/lib64", "/lib64" if not Path("/lib64").exists() else "/lib64_skip",
            ])
            # Mount /etc/alternatives nếu có (Debian/Ubuntu dùng update-alternatives)
            if Path("/etc/alternatives").exists():
                bwrap_cmd.extend(["--ro-bind", "/etc/alternatives", "/etc/alternatives"])
            bwrap_cmd.extend([
                "--tmpfs", "/tmp",
                "--tmpfs", "/run",
                "--proc", "/proc",
                "--dev", "/dev",
                "--bind", str(workspace_path), "/workspace",
                "--chdir", "/workspace",
            ])
            shell_exec = ["/bin/bash", "-c", command]

        # ============================================================
        # C. SECCOMP-BPF FILTER
        # ============================================================

        # Nạp Seccomp-BPF filter trực tiếp vào bwrap qua file descriptor.
        # bwrap đọc raw sock_filter[] binary từ fd, rồi gọi
        # prctl(PR_SET_NO_NEW_PRIVS, 1) + prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)
        if seccomp_fd is not None:
            bwrap_cmd.extend(["--seccomp", str(seccomp_fd)])

        # ============================================================
        # D. CÁC CỜ BẢO MẬT BỔ SUNG
        # ============================================================

        # --new-session: Gọi setsid() tạo session mới → ngăn chặn tấn công
        # TIOCSTI injection (inject keystroke vào terminal cha, CVE-2017-5226).
        bwrap_cmd.append("--new-session")

        # --die-with-parent: Tự động hủy sandbox khi tiến trình cha (Gateway)
        # bị kill → không để lại tiến trình zombie trên host.
        bwrap_cmd.append("--die-with-parent")

        # Gắn lệnh cần thực thi
        bwrap_cmd.extend(shell_exec)

        return bwrap_cmd

    def execute(
        self,
        command: str,
        workspace_dir: Optional[str] = None,
        network_enabled: bool = False,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Thực thi lệnh trong môi trường cô lập Bubblewrap.

        Luồng xử lý:
          1. Tạo sandbox_id duy nhất
          2. Tạo/lấy workspace directory
          3. Thiết lập Cgroups v2 (RAM, CPU, PIDs)
          4. Biên dịch Seccomp-BPF filter → pipe fd
          5. Xây dựng lệnh bwrap với đầy đủ isolation
          6. Chạy lệnh, thu thập kết quả
          7. Dọn dẹp: close fd, xóa workspace, xóa cgroup

        Args:
            command: Lệnh Bash hoặc chuỗi lệnh cần thực thi.
            workspace_dir: Thư mục workspace (nếu None → tạo tạm rồi xóa sau).
            network_enabled: Cho phép truy cập mạng hay không.
            timeout: Thời gian chạy tối đa (giây). None = dùng mặc định.

        Returns:
            Dict gồm: sandbox_id, stdout, stderr, exit_code, duration_ms, timed_out,
                       cgroup_usage (thống kê tài nguyên thực tế).
        """
        sandbox_id = str(uuid.uuid4())[:8]
        timeout_sec = timeout or self.default_timeout
        ephemeral_ws = False
        seccomp_fd = None

        # ===== 1. WORKSPACE SETUP =====
        if not workspace_dir:
            workspace_path = Path(f"/tmp/agent_sbx_{sandbox_id}")
            workspace_path.mkdir(parents=True, exist_ok=True)
            ephemeral_ws = True
        else:
            workspace_path = Path(workspace_dir)
            workspace_path.mkdir(parents=True, exist_ok=True)

        # ===== 2. CGROUPS V2 SETUP =====
        cgroup = CgroupManager(
            sandbox_id=sandbox_id,
            mem_max_mb=self.mem_limit_mb,
            cpu_quota_pct=self.cpu_quota_pct,
            pids_max=self.pids_max,
        )
        cgroup_active = cgroup.setup()

        # ===== 3. SECCOMP-BPF FILTER SETUP =====
        try:
            seccomp_fd = self._seccomp_builder.write_to_fd()
        except Exception as e:
            print(f"[Runner Warning] Không thể tạo Seccomp filter: {e}. Tiếp tục không có seccomp.")
            seccomp_fd = None

        # ===== 4. BUILD BWRAP COMMAND =====
        bwrap_cmd = self._build_bwrap_command(
            command=command,
            workspace_path=workspace_path,
            network_enabled=network_enabled,
            seccomp_fd=seccomp_fd,
        )

        # ===== 5. EXECUTE IN SANDBOX =====
        start_time = time.time()
        cgroup_usage = {}

        try:
            # Chuẩn bị danh sách fd cần kế thừa cho bwrap
            pass_fds = (seccomp_fd,) if seccomp_fd is not None else ()

            proc = subprocess.Popen(
                bwrap_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                close_fds=True,
                pass_fds=pass_fds,
                preexec_fn=os.setsid,
            )

            # Đóng seccomp fd ngay sau khi Popen (bwrap đã kế thừa, ta không cần nữa)
            if seccomp_fd is not None:
                try:
                    os.close(seccomp_fd)
                except OSError:
                    pass
                seccomp_fd = None  # Đánh dấu đã đóng

            # Đăng ký PID vào cgroup (nếu cgroup khả dụng)
            if cgroup_active:
                cgroup.add_process(proc.pid)

            try:
                stdout, stderr = proc.communicate(timeout=timeout_sec)
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                # Triệt tiêu toàn bộ process group nếu vượt timeout
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass  # Process đã kết thúc
                stdout, stderr = proc.communicate()
                exit_code = 124  # Mã thoát chuẩn cho timeout (giống GNU timeout)
                stderr = (stderr or "") + \
                    f"\n[Sandbox Timeout] Lệnh bị hủy do vượt quá giới hạn {timeout_sec}s!"

            # Thu thập thống kê cgroup trước khi cleanup
            if cgroup_active:
                cgroup_usage = cgroup.get_usage()

        except FileNotFoundError:
            stdout = ""
            stderr = "[Runner Error] Không tìm thấy lệnh 'bwrap'. Kiểm tra Bubblewrap đã cài đặt."
            exit_code = 127
        except Exception as e:
            stdout = ""
            stderr = f"[Runner Error]: {str(e)}"
            exit_code = 1
        finally:
            duration_ms = int((time.time() - start_time) * 1000)

            # Đóng seccomp fd nếu chưa đóng (trường hợp lỗi trước Popen)
            if seccomp_fd is not None:
                try:
                    os.close(seccomp_fd)
                except OSError:
                    pass

            # Dọn dẹp cgroup
            cgroup.cleanup()

            # Xóa workspace tạm (nếu là ephemeral)
            if ephemeral_ws and workspace_path.exists():
                shutil.rmtree(workspace_path, ignore_errors=True)

        return {
            "sandbox_id": sandbox_id,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "timed_out": exit_code == 124,
            "cgroup_usage": cgroup_usage,
        }


def benchmark(runner: SandboxRunner, iterations: int = 10) -> Dict[str, Any]:
    """
    Đo lường hiệu năng khởi tạo và thực thi Sandbox.

    Chạy một lệnh đơn giản (echo) nhiều lần và tính toán:
    - Cold start: Thời gian chạy lần đầu tiên (bao gồm cache miss)
    - Warm start: Trung bình thời gian chạy các lần sau (đã cache)
    - Min/Max/Average duration

    Args:
        runner: Instance SandboxRunner đã khởi tạo.
        iterations: Số lần chạy lặp lại.

    Returns:
        Dict chứa kết quả benchmark chi tiết.
    """
    durations = []
    test_cmd = "echo sandbox_benchmark_ok"

    print(f"[Benchmark] Đo lường hiệu năng Sandbox ({iterations} lần lặp)...")

    for i in range(iterations):
        result = runner.execute(test_cmd, timeout=10)
        durations.append(result["duration_ms"])

        if result["exit_code"] != 0:
            print(f"  [Lần {i+1}] LỖI: exit_code={result['exit_code']}, stderr={result['stderr']}")
        else:
            print(f"  [Lần {i+1}] OK - {result['duration_ms']}ms")

    cold_start = durations[0] if durations else 0
    warm_starts = durations[1:] if len(durations) > 1 else durations
    avg_warm = sum(warm_starts) / len(warm_starts) if warm_starts else 0

    results = {
        "iterations": iterations,
        "cold_start_ms": cold_start,
        "warm_start_avg_ms": round(avg_warm, 2),
        "min_ms": min(durations) if durations else 0,
        "max_ms": max(durations) if durations else 0,
        "avg_ms": round(sum(durations) / len(durations), 2) if durations else 0,
        "all_durations_ms": durations,
        "cold_start_target": "< 50ms",
        "warm_start_target": "< 10ms",
        "cold_start_pass": cold_start < 50,
        "warm_start_pass": avg_warm < 10 if warm_starts else False,
    }

    return results


if __name__ == "__main__":
    print("=" * 60)
    print("  CORE SANDBOX RUNNER - Kiểm thử & Đo lường")
    print("=" * 60)

    runner = SandboxRunner()

    # --- Test 1: Chạy lệnh cơ bản ---
    print("\n[Test 1] Chạy 'echo Hello && id && uname -a' trong Sandbox:")
    res = runner.execute("echo Hello from Sandbox && id && uname -a")
    print(f"  Stdout : {res['stdout'].strip()}")
    print(f"  Stderr : {res['stderr'].strip()}")
    print(f"  Exit   : {res['exit_code']}")
    print(f"  Time   : {res['duration_ms']}ms")
    print(f"  Sandbox: {res['sandbox_id']}")

    # --- Test 2: Kiểm tra Filesystem Read-Only ---
    print("\n[Test 2] Thử ghi file vào /usr (phải thất bại — Read-Only):")
    res = runner.execute("touch /usr/test_file 2>&1 || echo 'BLOCKED: Read-only filesystem'")
    print(f"  Stdout : {res['stdout'].strip()}")
    print(f"  Result : {'PASS ✓' if 'BLOCKED' in res['stdout'] or res['exit_code'] != 0 else 'FAIL ✗'}")

    # --- Test 3: Kiểm tra PID Namespace ---
    print("\n[Test 3] Kiểm tra PID Namespace (ps phải thấy rất ít process):")
    res = runner.execute("ps aux 2>/dev/null || echo 'PID namespace active'")
    print(f"  Stdout : {res['stdout'].strip()}")

    # --- Test 4: Kiểm tra Network Isolation ---
    print("\n[Test 4] Kiểm tra Network Isolation (ping phải thất bại):")
    res = runner.execute("ping -c 1 -W 1 8.8.8.8 2>&1 || echo 'BLOCKED: Network isolated'", timeout=5)
    print(f"  Stdout : {res['stdout'].strip()}")
    print(f"  Result : {'PASS ✓' if res['exit_code'] != 0 or 'BLOCKED' in res['stdout'] else 'FAIL ✗'}")

    # --- Test 5: Kiểm tra UTS Namespace (Hostname) ---
    print("\n[Test 5] Kiểm tra UTS Namespace (hostname phải là 'sandbox'):")
    res = runner.execute("hostname")
    hostname = res['stdout'].strip()
    print(f"  Hostname: {hostname}")
    print(f"  Result  : {'PASS ✓' if hostname == 'sandbox' else 'FAIL ✗'}")

    # --- Test 6: Kiểm tra Timeout ---
    print("\n[Test 6] Kiểm tra Timeout (sleep 100 với timeout 2s):")
    res = runner.execute("sleep 100", timeout=2)
    print(f"  Timed out: {res['timed_out']}")
    print(f"  Exit code: {res['exit_code']}")
    print(f"  Duration : {res['duration_ms']}ms")
    print(f"  Result   : {'PASS ✓' if res['timed_out'] else 'FAIL ✗'}")

    # --- Benchmark ---
    print("\n" + "=" * 60)
    print("  BENCHMARK - Đo lường hiệu năng")
    print("=" * 60)
    bench = benchmark(runner, iterations=10)
    print(f"\n  Kết quả:")
    print(f"    Cold Start     : {bench['cold_start_ms']}ms (Mục tiêu: {bench['cold_start_target']}) {'✓' if bench['cold_start_pass'] else '✗'}")
    print(f"    Warm Start AVG : {bench['warm_start_avg_ms']}ms (Mục tiêu: {bench['warm_start_target']}) {'✓' if bench['warm_start_pass'] else '✗'}")
    print(f"    Min / Max / Avg: {bench['min_ms']}ms / {bench['max_ms']}ms / {bench['avg_ms']}ms")
    print("=" * 60)
