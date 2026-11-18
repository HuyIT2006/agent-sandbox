# HƯỚNG DẪN TÍCH HỢP VÀ VẬN HÀNH GATEWAY (AGENT-SANDBOX)
**Tài liệu kỹ thuật Nhiệm vụ 2**: Agent Orchestration, Policy Engine & Tool Gateway
**Phiên bản**: 1.0.0 (Hoàn thiện Giai đoạn 4)

---

## 1. GIỚI THIỆU GATEWAY
API Gateway đóng vai trò là tầng kiểm soát bảo mật vòng ngoài (**Pre-Execution Guardrails**) và điều phối thực thi cho toàn bộ hệ thống AGENT-SANDBOX. Gateway cung cấp hai giao thức giao tiếp song song:
1. **Model Context Protocol (MCP)**: Cho phép các AI Agent (Cursor, Claude Desktop, LangChain, ReAct Agents) tương tác tự nhiên qua các công cụ chuẩn hóa.
2. **REST API (FastAPI)**: Cung cấp endpoint HTTP phục vụ tích hợp dịch vụ, quản trị viên, và phê duyệt Human-in-the-Loop (HITL).

---

## 2. KIẾN TRÚC CÁC MODULE THUỘC NHIỆM VỤ 2
Toàn bộ mã nguồn nằm độc lập trong thư mục `gateway/`:
- `gateway/inspector.py`: Bộ kiểm tra cú pháp tĩnh nâng cao sử dụng `ast.NodeVisitor` cho Python và `bashlex` AST cho Bash. Áp dụng nguyên tắc **Fail-Closed**.
- `gateway/policy.py`: Dynamic Policy Engine hỗ trợ Risk Matrix (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), Dynamic Rules (`allowlist`, `denylist`), và quản lý vòng đời `confirmation_token`.
- `gateway/session_manager.py`: Quản lý vòng đời phiên làm việc, tự động lưu metadata trên Redis với TTL, hỗ trợ In-memory Fallback và phòng vệ Path Traversal.
- `gateway/api.py`: FastAPI server cung cấp các endpoint REST (`/health`, `/api/v1/execute`, `/api/v1/confirm`).
- `gateway/mcp_server.py`: Model Context Protocol Server cung cấp 4 công cụ chuẩn cho AI Agent qua Stdio Transport.
- `gateway/agent_demo.py`: Kịch bản AI Agent Client mẫu kết nối MCP Server và điều phối 4 luồng tác vụ.

---

## 3. VAI TRÒ CỦA MCP SERVER
MCP Server chuẩn hóa giao tiếp giữa các mô hình ngôn ngữ lớn (LLM / Agent) và môi trường Sandbox. Thay vì cho phép Agent tự do gửi lệnh thô tới hệ điều hành, MCP Server:
- Buộc mọi yêu cầu phải khai báo cấu trúc input rõ ràng.
- Đưa 100% lệnh qua phễu an ninh: `Inspector` ➔ `Policy` ➔ `Session` ➔ `HITL` ➔ `SandboxRunner`.
- Ngăn chặn Agent tự ý truy cập các tệp tin ngoài workspace được cấp.

---

## 4 & 5. DANH SÁCH VÀ SCHEMA 4 CÔNG CỤ MCP

### 1. `execute_bash`
- **Mục đích**: Chạy lệnh Bash trong môi trường Linux Sandbox được cách ly kernel.
- **Input**:
  - `command` (str, bắt buộc): Câu lệnh Bash.
  - `session_id` (str, tùy chọn): ID phiên làm việc.
  - `allow_network` (bool, mặc định `false`): Yêu cầu quyền mạng (sẽ chuyển sang HITL nếu `true`).
  - `timeout` (int, mặc định `20`): Thời gian chạy tối đa (1-60s).
- **Output**: JSON string gồm `success`, `status` (`EXECUTED` | `REQUIRE_CONFIRMATION` | `REJECT`), `stdout`, `stderr`, `exit_code`, `duration_ms`.

### 2. `execute_python`
- **Mục đích**: Thực thi mã Python an toàn qua file script tạm thời trong workspace.
- **Input**:
  - `code` (str, bắt buộc): Mã nguồn Python.
  - `session_id` (str, tùy chọn): ID phiên làm việc.
  - `allow_network` (bool, mặc định `false`): Yêu cầu quyền mạng.
  - `timeout` (int, mặc định `20`): Thời gian chạy tối đa.
- **Output**: JSON string gồm kết quả thực thi và lý do quyết định của Policy.

### 3. `read_workspace_file`
- **Mục đích**: Đọc nội dung tệp tin văn bản bên trong workspace của session.
- **Input**:
  - `session_id` (str, bắt buộc): ID phiên.
  - `path` (str, bắt buộc): Đường dẫn tương đối bên trong workspace.
- **Output**: JSON string gồm `success`, `path`, `size_bytes`, `content` (UTF-8).

### 4. `write_workspace_file`
- **Mục đích**: Ghi nội dung vào tệp tin bên trong workspace của session.
- **Input**:
  - `session_id` (str, bắt buộc): ID phiên.
  - `path` (str, bắt buộc): Đường dẫn tương đối bên trong workspace.
  - `content` (str, bắt buộc): Nội dung cần ghi.
- **Output**: JSON string gồm `success`, `path`, `bytes_written`, `status: "SUCCESS"`.

---

## 6. THIẾT LẬP MÔI TRƯỜNG VIRTUAL ENVIRONMENT
Dự án sử dụng môi trường ảo độc lập, không can thiệp vào Python toàn hệ thống:
```bash
# Tạo virtual environment tại đường dẫn riêng
python -m venv %LOCALAPPDATA%\venvs\agent-sandbox-env

# Kích hoạt môi trường (Windows PowerShell)
& "$env:LOCALAPPDATA\venvs\agent-sandbox-env\Scripts\Activate.ps1"

# Cài đặt các thư viện được quy định
pip install "bashlex>=0.18" "fastapi>=0.115.0" "pydantic>=2.9.0" "pytest>=8.3.0" "redis>=5.1.0" "mcp>=1.0.0"
```

---

## 7. CÁCH KHỞI ĐỘNG MCP SERVER
MCP Server mặc định sử dụng **Stdio Transport**:
```bash
# Khởi động trực tiếp MCP Server
python -m gateway.mcp_server
```

---

## 8. CẤU HÌNH MCP CLIENT CHO AI AGENTS
Thêm cấu hình sau vào tệp cấu hình MCP của client (ví dụ `claude_desktop_config.json` hoặc cấu hình Agent IDE):
```json
{
  "mcpServers": {
    "agent-sandbox": {
      "command": "C:\\Users\\Anh Kiet\\AppData\\Local\\venvs\\agent-sandbox-env\\Scripts\\python.exe",
      "args": ["-m", "gateway.mcp_server"]
    }
  }
}
```

---

## 9. CÁCH CHẠY AI AGENT DEMO
Kịch bản demo mô phỏng 4 tình huống tương tác thực tế giữa AI Agent và Sandbox:
```bash
python -m gateway.agent_demo
```
Kết quả chạy sẽ lần lượt thực hiện:
1. Thực thi mã Python tính toán và chuẩn hóa chuỗi.
2. Ghi tệp báo cáo vào workspace và đọc lại để đối soát toàn vẹn.
3. Thử nghiệm mã độc `import os` và chứng minh hệ thống chặn đứng ở tầng Inspector.
4. Thử nghiệm lệnh mạng `allow_network=True` và nhận `confirmation_token` cho quy trình HITL.

---

## 10. CÁCH GỌI REST API
Khởi động REST API Server:
```bash
uvicorn gateway.api:app --host 0.0.0.0 --port 8000
```
- **Kiểm tra sức khỏe**: `GET http://localhost:8000/health`
- **Tài liệu Swagger tương tác**: `http://localhost:8000/docs`
- **Gửi yêu cầu thực thi**:
  ```bash
  curl -X POST http://localhost:8000/api/v1/execute \
    -H "Content-Type: application/json" \
    -d '{"tool_type": "bash", "code": "echo Hello from Sandbox!"}'
  ```

---

## 11. HƯỚNG DẪN QUY TRÌNH HUMAN-IN-THE-LOOP (HITL)
Khi yêu cầu rơi vào trạng thái `REQUIRE_CONFIRMATION` (do rủi ro `HIGH` hoặc yêu cầu cờ `allow_network=True`):
1. Hệ thống trả về `confirmation_token` (entropy cao 256-bit, có hạn dùng `expires_in`).
2. Lệnh gốc được tạm giữ an toàn trên server, **SandboxRunner chưa được gọi**.
3. Người vận hành có thẩm quyền xem xét và gửi quyết định qua REST API:
   - **Phê duyệt (APPROVED)**:
     ```bash
     curl -X POST http://localhost:8000/api/v1/confirm \
       -H "Content-Type: application/json" \
       -d '{"confirmation_token": "<TOKEN_CUA_BAN>", "decision": "APPROVED"}'
     ```
   - **Từ chối (REJECTED)**:
     ```bash
     curl -X POST http://localhost:8000/api/v1/confirm \
       -H "Content-Type: application/json" \
       -d '{"confirmation_token": "<TOKEN_CUA_BAN>", "decision": "REJECTED"}'
     ```
4. **Lưu ý**: Mỗi token chỉ sử dụng được 1 lần (Single-use, chống Replay). Ngay cả khi được `APPROVED`, nếu mã nguồn chứa vi phạm `CRITICAL`, hệ thống vẫn kiên quyết từ chối thực thi.

---

## 12. CẤU HÌNH REDIS VÀ FALLBACK
- Cấu hình qua biến môi trường:
  ```bash
  export REDIS_URL="redis://localhost:6379/0"
  ```
- **Khả năng phục hồi (Resilience)**: Nếu Redis server offline hoặc timeout, `SessionManager` tự động kích hoạt **In-memory Fallback mode**. Endpoint `/health` luôn hiển thị trạng thái `session_backend: "REDIS"` hoặc `"IN_MEMORY"`.

---

## 13 & 14. HƯỚNG DẪN CHẠY KIỂM THỬ (TEST SUITE)
Tất cả các bài kiểm thử đều được thực hiện thông qua `pytest`:
```bash
# Chạy toàn bộ test suite (Unit Tests, MCP Protocol, HITL, E2E)
pytest gateway/tests/ -v

# Chạy riêng từng bộ kiểm thử
pytest gateway/tests/test_inspector.py -v       # Bộ test AST và Bashlex
pytest gateway/tests/test_policy_session.py -v   # Bộ test Policy, HITL, Session
pytest gateway/tests/test_mcp_server.py -v       # Bộ test MCP Server
pytest gateway/tests/test_gateway_e2e.py -v      # Bộ test End-to-End
```

---

## 15. GIẢI THÍCH GIỚI HẠN KHI CHẠY TRÊN WINDOWS
- `SandboxRunner` phụ thuộc vào **Bubblewrap (`bwrap`)**, Linux Namespaces và Cgroups v2 – những công nghệ đặc thù của Linux Kernel.
- Khi chạy trực tiếp trên Windows host (không qua Docker/WSL), `SandboxRunner` sẽ báo lỗi thiếu `bwrap`.
- **Giải pháp xử lý của Gateway**: API Gateway và MCP Server đã được bọc cơ chế xử lý lỗi an toàn. Khi chạy trên Windows dev/test, toàn bộ logic AST Parser, Policy Engine, HITL Token, Session Manager, Workspace Files và MCP Protocol **hoạt động thực tế 100%**. Việc gọi thực thi lệnh Sandbox được mock an toàn để phục vụ kiểm thử mà không phá vỡ quy trình.

---

## 16. CÁC LƯU Ý BẢO MẬT KHI TRIỂN KHAI PRODUCTION (LINUX/DOCKER)
1. **Chạy trong Container Privileged có kiểm soát**: Dùng `docker compose up -d` theo đúng cấu hình của dự án để container có quyền tạo User Namespaces cho `bwrap`.
2. **Bảo vệ Endpoint Phê duyệt HITL**: Endpoint `POST /api/v1/confirm` cần được đặt sau lớp xác thực quản trị (Admin Authentication / mTLS / API Key) để ngăn chặn kẻ xấu chiếm đoạt token.
3. **Phòng thủ Đa tầng (Defense-in-Depth)**: AST Inspector và Policy Engine là chốt chặn lọc mã tĩnh; chốt chặn cách ly hệ thống và tài nguyên thuộc về Linux Sandbox (`bwrap` + `seccomp` + `cgroups`) của Thành viên 1 và Egress Firewall của Thành viên 3.
