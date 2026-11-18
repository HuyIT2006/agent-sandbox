# 📌 BÁO CÁO SETUP DỰ ÁN & HƯỚNG DẪN DÀNH CHO CÁC THÀNH VIÊN
> **Dự án**: Secure Agentic AI Tool Execution using Linux Sandbox  
> **Cập nhật ngày**: 04/11/2026  
> **Tài liệu tham khảo chi tiết**: [`README.md`](README.md) và [`plan.md`](plan.md)

---

## I. DỰ ÁN NÀY LÀ GÌ?
Dự án xây dựng một hệ thống **Sandbox Linux an toàn, đa tầng bảo vệ** để AI Agent (như ChatGPT, Claude, AutoGPT, ReAct Agent) có thể tự do chạy các công cụ (lệnh Bash, script Python, công cụ MCP) mà **không thể phá hoại, rò rỉ dữ liệu hoặc chiếm quyền điều khiển máy chủ (Host OS)**.

---

## II. NHỮNG GÌ ĐÃ ĐƯỢC SETUP VÀ LẬP TRÌNH SẴN TRONG DỰ ÁN

Hiện tại toàn bộ khung sườn kỹ thuật của 3 tầng bảo mật đã được cài đặt và tích hợp sẵn trong repo:

### 1. Đóng gói Container & Dịch vụ ("Zero-Setup")
- **`Dockerfile` (Ubuntu 24.04)**: Đã cấu hình sẵn toàn bộ môi trường Linux Sandbox, Python 3, venv và tự động tải **Alpine Mini RootFS (v3.20)** để làm hệ điều hành Read-Only cho Sandbox.
- **`docker-compose.yml`**:
  - `agent_sandbox_gateway` (Port `8000`): Chạy Tool Execution API với quyền privileged (để tạo Linux Namespaces bên trong).
  - `agent_sandbox_redis` (Port `6380:6379`): Quản lý trạng thái phiên làm việc (Session) và rate limiting.

### 2. Các công cụ Hệ điều hành & Bảo mật Linux (OS-Level)
- **`bubblewrap` (`bwrap`)**: Lõi thực thi Sandbox. Tự động cô lập:
  - **Namespaces**: `--unshare-pid`, `--unshare-ipc`, `--unshare-uts`, `--unshare-cgroup`, `--unshare-net`.
  - **Filesystem**: Gắn rootfs Read-Only, thư mục làm việc `/tmp` dùng `tmpfs` (tự hủy sạch dấu vết khi xong việc).
  - Tốc độ khởi động siêu tốc: **~24ms**.
- **`cgroups v2`**: Quản lý tài nguyên trong `core/cgroup_manager.py`:
  - Giới hạn RAM: Tối đa **256MB** (`memory.max`).
  - Giới hạn CPU: Tối đa **50%** 1 core (`cpu.max`).
  - Giới hạn PIDs: Tối đa **32 tiến trình** (`pids.max` — chặn đứng Fork Bomb).
- **`seccomp-bpf`**: Profile `core/seccomp/seccomp_profile.json` chặn hơn 20 syscall nguy hiểm (`ptrace`, `bpf`, `mount`, `reboot`, `sys_chroot`, `setns`,...).
- **Network Isolation & Firewall**:
  - `setup_netns.sh`: Cách ly mạng bằng Network Namespace + `veth pair`.
  - `iptables`: Chặn SSRF, chặn IP Cloud Metadata (`169.254.169.254`), chặn toàn bộ IP mạng nội bộ LAN (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **`bpftrace` (eBPF Telemetry)**: File `telemetry/ebpf/tracer.bt` theo dõi kernel thời gian thực các syscall `execve`, `connect`, và cảnh báo khi có tiến trình chạm vào `/etc/shadow`, `/etc/passwd`.

### 3. Thư viện Python (`requirements.txt`)
- **FastAPI + Uvicorn + Pydantic**: Xây dựng REST API Gateway với tài liệu tự động Swagger UI (`http://localhost:8000/docs`).
- **Anthropic MCP SDK (`mcp`)**: Chuẩn Model Context Protocol kết nối với AI Agent.
- **AST & Regex Inspection (`ast`, `bashlex`)**:
  - Kiểm tra mã Python bằng cây cú pháp trừu tượng AST: Chặn các thư viện (`os`, `subprocess`, `socket`, `ctypes`,...) và hàm nguy hiểm (`eval`, `exec`, `open`).
  - Kiểm tra lệnh Bash: Nhận diện lệnh phá hoại (`rm -rf /`), Reverse Shell, obfuscated base64, tải script từ web (`curl | bash`).
- **Redis (`redis-py`)**: Lưu trữ và quản lý dọn dẹp các thư mục workspace tạm sau thời gian hết hạn (TTL).
- **Pytest, HTTPX, Psutil**: Phục vụ kiểm thử API và đo đạc tài nguyên.

### 4. Bộ Kiểm thử Tấn công Tự động (Red Teaming Suite)
File `telemetry/redteam/test_exploits.py` đã sẵn sàng với **5 bài test thực tế**:
1. Thử đọc trộm `/etc/shadow` $\rightarrow$ **Bị chặn (Permission denied)**.
2. Thử ghi đè file vào `/usr/` $\rightarrow$ **Bị chặn (Read-only filesystem)**.
3. Thử chạy mã Python độc hại (`os.system`) $\rightarrow$ **Bị AST Inspector từ chối**.
4. Thử chạy lệnh Bash phá hoại (`rm -rf /`) $\rightarrow$ **Bị Shell Inspector từ chối**.
5. Thử kết nối Internet trong chế độ cách ly $\rightarrow$ **Bị chặn (Unshare network)**.

---

## III. YÊU CẦU CÁC THÀNH VIÊN TRONG NHÓM CẦN SETUP GÌ?

> [!IMPORTANT]
> **CÓ CẦN MÁY UBUNTU THẬT KHÔNG?**  
> **KHÔNG HỀ BẮT BUỘC!** Các thành viên hoàn toàn **không cần cài lại máy thành Ubuntu vật lý** hay cài dual-boot phức tạp. Bạn có thể dùng bất kỳ môi trường nào sau đây:
> 1. **Máy ảo VMware Workstation / VirtualBox cài Ubuntu**: Rất khuyến khích cho đồ án an ninh mạng/hệ điều hành vì vừa có nhân Linux hoàn chỉnh (đầy đủ quyền root, cgroups, eBPF) vừa cô lập an toàn, không sợ ảnh hưởng đến máy chính.
> 2. **WSL2 trên Windows (Ubuntu 22.04 / 24.04)**: Cực kỳ nhẹ, tiện lợi, tích hợp sẵn VS Code.
> 3. **Docker Desktop (Windows / macOS / Linux)**: Chỉ cần bật Docker lên là chạy ngay.

Nhóm có thể chọn **1 trong 2 cách triển khai** sau:

---

### 👉 LỰA CHỌN 1: Dùng Docker (Khuyên dùng cho cả nhóm - Nhanh nhất & Không sợ xung đột môi trường)

Dành cho mọi thành viên muốn chạy, test code, làm API hoặc demo cho giảng viên mà không cần cấu hình sâu.

#### 1. Yêu cầu trên máy cá nhân:
- Đã cài đặt **Git**, **Docker** và **Docker Compose** (trên Windows dùng Docker Desktop kết hợp WSL2, macOS, hoặc Linux).

#### 2. Các bước thực hiện:
```bash
# Bước 1: Clone dự án về máy
git clone <URL_REPO_CUA_NHOM>
cd agent-sandbox

# Bước 2: Khởi chạy toàn bộ hệ thống bằng Docker Compose (chỉ 1 lệnh duy nhất)
docker compose up -d
```

#### 3. Kiểm tra xem hệ thống đã chạy tốt chưa:
- **Kiểm tra API**: Mở trình duyệt vào `http://localhost:8000/docs` (Swagger UI).
- **Kiểm tra Healthcheck**:
  ```bash
  curl http://localhost:8000/health
  # Kết quả trả về: {"status":"ok","service":"agent-sandbox-gateway"}
  ```
- **Chạy toàn bộ 5 bài test bảo mật Red Team**:
  ```bash
  docker exec agent_sandbox_gateway python3 telemetry/redteam/test_exploits.py
  ```

---

### 👉 LỰA CHỌN 2: Setup trên Máy ảo hoặc Máy Linux Host (Dành riêng cho Dev chuyên sâu)

Dành cho thành viên phụ trách **Kernel / eBPF / Network (TV 1 & TV 3)** khi cần can thiệp trực tiếp vào kernel syscall và script `bpftrace`.

#### 1. Yêu cầu trên máy cá nhân:
- Sử dụng **Máy ảo VMware / VirtualBox** hoặc **WSL2** hoặc máy thật cài **Ubuntu 22.04 LTS hoặc 24.04 LTS**.
- Có quyền `sudo` (root).
- Nhân Linux hỗ trợ **Cgroups v2** (đã mặc định có trên Ubuntu 22.04/24.04).

#### 2. Cài đặt tự động bằng 1 script duy nhất:
Trong thư mục dự án đã có sẵn script tự động tải mọi gói hệ điều hành, rootfs và thư viện:
```bash
# Chạy script setup môi trường
chmod +x scripts/setup_env.sh
./scripts/setup_env.sh
```

#### 3. Kích hoạt môi trường và chạy Gateway API:
```bash
# Kích hoạt virtualenv Python
source venv/bin/activate

# Khởi động API Gateway
uvicorn gateway.api:app --host 0.0.0.0 --port 8000 --reload
```

---

## IV. BẢNG PHÂN CHIA NHIỆM VỤ TIẾP THEO CHO TỪNG THÀNH VIÊN

Dựa trên kế hoạch chi tiết tại [`plan.md`](plan.md), nhiệm vụ cụ thể của từng bạn như sau:

| Thành viên | Trách nhiệm chính | File cần làm việc tiếp theo | Nhiệm vụ sắp tới |
| :--- | :--- | :--- | :--- |
| **Thành viên 1**<br>*(Core Sandbox & Isolation)* | Lõi cách ly Linux, Namespaces, Cgroups, Seccomp | `core/runner.py`<br>`core/cgroup_manager.py`<br>`core/seccomp/` | - Đo đạc và tối ưu độ trễ khởi động (Cold Start < 50ms).<br>- Tích hợp load seccomp BPF filter trực tiếp vào `bwrap`.<br>- Tối ưu dung lượng Alpine rootfs. |
| **Thành viên 2**<br>*(Gateway & Policy Engine)* | API Gateway, Quản lý Session, Phân tích AST, MCP | `gateway/api.py`<br>`gateway/inspector.py`<br>`gateway/policy.py`<br>`gateway/session_manager.py` | - Mở rộng tập luật cấm trong AST (phát hiện eval/exec biến tướng).<br>- Hoàn thiện chuẩn MCP Server cho AI Agent.<br>- Viết 1 script kịch bản Agent demo (dùng OpenAI / Gemini / LangChain gọi Sandbox). |
| **Thành viên 3**<br>*(Network, eBPF & Red Teaming)* | Mạng an toàn, Egress Firewall, eBPF Trace, Pentest | `telemetry/network/setup_netns.sh`<br>`telemetry/ebpf/tracer.bt`<br>`telemetry/redteam/test_exploits.py` | - Chạy thử `tracer.bt` xuất log JSON khi có vi phạm.<br>- Thử nghiệm cơ chế Auto-Killswitch (gửi SIGKILL khi phát hiện vượt rào).<br>- Bổ sung thêm các kịch bản test: Container Escape, Fork bomb, Prompt Injection. |

---

## V. CÁC LỆNH TEST NHANH THƯỜNG DÙNG

1. **Test chạy một lệnh Bash hợp lệ qua API**:
   ```bash
   curl -s -X POST http://localhost:8000/api/v1/execute \
     -H "Content-Type: application/json" \
     -d '{"tool_type": "bash", "code": "echo Hello from Sandbox! && uname -a"}'
   ```

2. **Test chạy một đoạn code Python tính toán**:
   ```bash
   curl -s -X POST http://localhost:8000/api/v1/execute \
     -H "Content-Type: application/json" \
     -d '{"tool_type": "python", "code": "print(sum([i**2 for i in range(10)]))"}'
   ```

3. **Test gửi mã độc Python (Hệ thống sẽ từ chối ngay lập tức)**:
   ```bash
   curl -s -X POST http://localhost:8000/api/v1/execute \
     -H "Content-Type: application/json" \
     -d '{"tool_type": "python", "code": "import os; os.system(\"cat /etc/shadow\")"}'
   ```
   *(Sẽ nhận phản hồi: `status: REJECT`, `reason: Phát hiện rủi ro mức độ CRITICAL: Import thư viện nhạy cảm: 'os'`)*

