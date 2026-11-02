# Secure Agentic AI Tool Execution using Linux Sandbox

> **Mục tiêu**: Xây dựng môi trường Sandbox Linux an toàn, hiệu năng cao và có khả năng kiểm soát chặt chẽ (isolation, policy enforcement, network egress control, audit log) để phục vụ cho AI Agent thực thi các công cụ (Bash, Python, MCP tools) mà không gây rủi ro cho máy chủ chủ quản (Host OS).

---

## ⚡ Khởi Động "Zero-Setup" bằng Docker (Dành cho Cả 3 Thành viên)

Tất cả môi trường (Linux kernel sandbox runtime, Bubblewrap, Alpine rootfs, Python 3, FastAPI, Redis session cache, thư viện) **đã được đóng gói sẵn 100%**. 

Các thành viên trong nhóm khi clone dự án về **chỉ cần chạy đúng 1 lệnh duy nhất** mà không cần cài đặt thêm bất kỳ thư viện hay cấu hình thủ công nào trên máy:

```bash
docker compose up -d
```

### Kiểm tra dịch vụ hoạt động:
1. **Kiểm tra trạng thái Health Check**:
   ```bash
   curl http://localhost:8000/health
   # Trả về: {"status":"ok","service":"agent-sandbox-gateway"}
   ```

2. **Tài liệu Swagger UI tương tác trực tiếp**:
   Mở trình duyệt: `http://localhost:8000/docs`

3. **Chạy toàn bộ 5 bài kiểm thử bảo mật (Red Teaming Suite)**:
   ```bash
   docker exec agent_sandbox_gateway python3 telemetry/redteam/test_exploits.py
   ```

---

## 📁 Cấu trúc Thư mục Dự án (Project Layout)

```
agent-sandbox/
├── core/                                # [Thành viên 1] Kernel Isolation & Sandbox Engine
│   ├── runner.py                        # Execution runner sử dụng bwrap (Cold start ~24ms)
│   ├── cgroup_manager.py                # Quản lý giới hạn RAM (256MB), CPU (50%), PIDs (chống Fork Bomb)
│   ├── download_rootfs.sh               # Script tải và chuẩn bị Alpine rootfs tối giản
│   └── seccomp/                         # Seccomp-BPF profiles chặn syscall nguy hiểm
│
├── gateway/                             # [Thành viên 2] API Gateway & Policy Engine
│   ├── api.py                           # FastAPI Server cung cấp endpoint /api/v1/execute
│   ├── inspector.py                     # AST Analyzer (Python) & Shell pattern detector
│   ├── policy.py                        # Dynamic Policy & Decision Engine
│   └── session_manager.py               # Quản lý phiên làm việc & workspace tạm
│
├── telemetry/                           # [Thành viên 3] Network Security, eBPF & Red Teaming
│   ├── network/
│   │   └── setup_netns.sh               # Thiết lập Network Namespace + Firewall chặn SSRF
│   ├── ebpf/
│   │   └── tracer.bt                    # bpftrace script bắt syscall (execve, connect, openat)
│   └── redteam/
│       └── test_exploits.py             # Bộ test-suite Red Teaming kiểm thử tấn công tự động
│
├── Dockerfile                           # Môi trường đóng gói đầy đủ Sandbox, bwrap, Alpine rootfs & Python
├── docker-compose.yml                   # Docker Compose khởi chạy Gateway API + Redis
├── requirements.txt                     # Danh sách thư viện Python
├── plan.md                              # Kế hoạch chi tiết của dự án
└── README.md
```

---

## 🛠️ Hướng dẫn Kiểm thử Chi tiết Cho Từng Thành viên

### 1. Thành viên 1: Core Sandbox & Linux OS Isolation
Chạy thử nghiệm lệnh bên trong Sandbox từ container:
```bash
docker exec agent_sandbox_gateway python3 core/runner.py
```
*Thời gian khởi tạo & thực thi:* **~24ms**.

### 2. Thành viên 2: API Gateway & AST Inspector
Thử gửi request thực thi lệnh Bash hoặc script Python qua API:
- **Bash command**:
  ```bash
  curl -s -X POST http://localhost:8000/api/v1/execute \
    -H "Content-Type: application/json" \
    -d '{"tool_type": "bash", "code": "echo Hello from Sandbox! && uname -a"}'
  ```
- **Python script**:
  ```bash
  curl -s -X POST http://localhost:8000/api/v1/execute \
    -H "Content-Type: application/json" \
    -d '{"tool_type": "python", "code": "print(2**100)"}'
  ```
- **Thử gửi mã độc (sẽ bị AST Inspector từ chối ngay)**:
  ```bash
  curl -s -X POST http://localhost:8000/api/v1/execute \
    -H "Content-Type: application/json" \
    -d '{"tool_type": "python", "code": "import os; os.system(\"id\")"}'
  ```

### 3. Thành viên 3: Network Security & Red Teaming
- **Chạy kiểm thử tấn công tự động**:
  ```bash
  docker exec agent_sandbox_gateway python3 telemetry/redteam/test_exploits.py
  ```
- **Chạy script giám sát eBPF trên máy host**:
  ```bash
  sudo bpftrace telemetry/ebpf/tracer.bt
  ```
- **Cấu hình Network Namespace & Firewall Egress chống SSRF**:
  ```bash
  sudo chmod +x telemetry/network/setup_netns.sh
  sudo ./telemetry/network/setup_netns.sh
  ```
