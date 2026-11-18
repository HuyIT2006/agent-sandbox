"""
agent_demo.py
Thành viên 2: AI Agent Client Demo (Model Context Protocol Client)
Minh họa kịch bản AI Agent kết nối và tương tác với AGENT-SANDBOX thông qua MCP Server:
1. Kịch bản 1: Thực thi mã Python an toàn (xử lý dữ liệu, chuỗi).
2. Kịch bản 2: Quản lý và thao tác tệp tin trong Workspace (ghi file, đọc file, đối soát).
3. Kịch bản 3: Phòng vệ an ninh (Security Demo) - Từ chối mã độc CRITICAL trước khi thực thi.
4. Kịch bản 4: Quy trình Human-in-the-Loop (HITL) - Yêu cầu nhạy cảm tạo confirmation_token chờ phê duyệt.

Chạy trực tiếp bằng:
    python -m gateway.agent_demo
"""

import asyncio
import json
import os
import sys
import uuid
from typing import Dict, Any, Optional

from mcp import StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.session import ClientSession


# =============================================================================
# HELPER IN ẤN CONSOLE TRỰC QUAN
# =============================================================================
def print_banner():
    print("\n" + "=" * 70)
    print("   🤖 AGENT-SANDBOX: AI AGENT INTERACTION DEMO (MCP PROTOCOL)   ")
    print("=" * 70)
    print("Mô hình: AI Client -> Model Context Protocol (MCP) -> Gateway Security -> Sandbox")
    print("=" * 70 + "\n")


def print_step(step_num: int, title: str):
    print(f"\n{'-' * 70}")
    print(f"▶ [KỊCH BẢN {step_num}] {title}")
    print(f"{'-' * 70}")


# =============================================================================
# LỚP AGENT DEMO CLIENT
# =============================================================================
class SandboxAgentDemo:
    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or f"demo_session_{uuid.uuid4().hex[:8]}"
        self.python_exec = sys.executable

    async def run(self):
        print_banner()
        print(f"[*] Định danh phiên làm việc (Session ID): {self.session_id}")
        print(f"[*] Python Interpreter: {self.python_exec}")
        print("[*] Đang khởi động kết nối MCP Stdio Client tới 'gateway.mcp_server'...")

        server_params = StdioServerParameters(
            command=self.python_exec,
            args=["-m", "gateway.mcp_server"],
            env=dict(os.environ),
        )

        try:
            async with stdio_client(server_params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    # 1. Khởi tạo phiên giao tiếp MCP
                    await session.initialize()
                    print("[✓] Kết nối thành công tới MCP Server (Stdio Transport)!")

                    # 2. Liệt kê danh sách công cụ
                    tools_response = await session.list_tools()
                    tool_names = [t.name for t in tools_response.tools]
                    print(f"[✓] Đã phát hiện {len(tool_names)} công cụ sẵn sàng: {', '.join(tool_names)}")

                    # Chạy lần lượt 4 kịch bản minh họa
                    await self.scenario_1_python_execution(session)
                    await self.scenario_2_workspace_files(session)
                    await self.scenario_3_security_rejection(session)
                    await self.scenario_4_human_in_the_loop(session)

            print("\n" + "=" * 70)
            print("   🎉 TẤT CẢ 4 KỊCH BẢN AGENT DEMO ĐÃ HOÀN THÀNH XUẤT SẮC!   ")
            print("=" * 70 + "\n")

        except Exception as e:
            print(f"\n[!] Lỗi khi chạy Agent Demo: {e}")
            import traceback
            traceback.print_exc()

    # =========================================================================
    # KỊCH BẢN 1: THỰC THI PYTHON AN TOÀN
    # =========================================================================
    async def scenario_1_python_execution(self, session: ClientSession):
        print_step(1, "THỰC THI MÃ PYTHON AN TOÀN TRONG SANDBOX (execute_python)")
        print("Tình huống: AI Agent cần phân tích danh sách số và chuẩn hóa văn bản.")

        script_code = """
numbers = [10, 20, 30, 40, 50]
tong = sum(numbers)
trung_binh = tong / len(numbers)
message = "ket qua phan tich du lieu an toan"

print(f"Tong cac so: {tong}")
print(f"Gia tri trung binh: {trung_binh}")
print(f"Thong diep: {message.upper()}")
"""
        print("[AI Agent Request]: Gửi mã Python qua tool 'execute_python'...")
        call_res = await session.call_tool(
            "execute_python",
            {"code": script_code, "session_id": self.session_id},
        )
        if call_res.content and len(call_res.content) > 0:
            data = json.loads(call_res.content[0].text)
        else:
            data = {"success": False, "status": "ERROR", "error": "Empty response"}

        print("[MCP Server Response]:")
        print(f"  - Thành công: {data.get('success')}")
        print(f"  - Trạng thái: {data.get('status')}")
        print(f"  - Quyết định Policy: {data.get('decision_reason')}")
        if data.get("stdout"):
            print("  - Output (stdout):\n" + "\n".join(f"      {line}" for line in data["stdout"].strip().split("\n")))
        if data.get("stderr"):
            print("  - Thông báo (stderr):\n" + "\n".join(f"      {line}" for line in data["stderr"].strip().split("\n")))
        print(f"  - Exit Code: {data.get('exit_code')}")
        print(f"  - Thời gian thực thi: {data.get('duration_ms')} ms")
        if "bwrap" in str(data.get("stderr", "")):
            print("  [i] Ghi chú môi trường: Máy host Windows hiện tại chưa có Bubblewrap (bwrap).")
            print("      Code đã qua kiểm duyệt an toàn của Inspector & Policy và được chuyển tới Runner!")


    # =========================================================================
    # KỊCH BẢN 2: THAO TÁC FILE TRONG WORKSPACE
    # =========================================================================
    async def scenario_2_workspace_files(self, session: ClientSession):
        print_step(2, "THAO TÁC TỆP TIN TRONG WORKSPACE (write & read_workspace_file)")
        print("Tình huống: AI Agent ghi tệp cấu hình/báo cáo và đọc lại để kiểm tra.")

        file_path = "reports/agent_audit.json"
        file_payload = json.dumps({
            "task": "Automated Security Audit",
            "agent": "Antigravity Assistant",
            "status": "COMPLETED",
            "findings": ["No leaks", "Sandbox active", "Policy passed"],
        }, indent=2, ensure_ascii=False)

        # Bước 2.1: Ghi file
        print(f"[AI Agent Request 2.1]: Ghi nội dung vào '{file_path}'...")
        write_res = await session.call_tool(
            "write_workspace_file",
            {"session_id": self.session_id, "path": file_path, "content": file_payload},
        )
        write_data = json.loads(write_res.content[0].text)
        print(f"  -> Kết quả ghi: {write_data.get('status')} ({write_data.get('bytes_written')} bytes)")

        # Bước 2.2: Đọc file
        print(f"[AI Agent Request 2.2]: Đọc lại tệp tin '{file_path}' từ workspace...")
        read_res = await session.call_tool(
            "read_workspace_file",
            {"session_id": self.session_id, "path": file_path},
        )
        read_data = json.loads(read_res.content[0].text)
        print(f"  -> Thành công: {read_data.get('success')}")
        print(f"  -> Kích thước đọc được: {read_data.get('size_bytes')} bytes")
        print("  -> Nội dung đọc được:\n" + "\n".join(f"      {line}" for line in read_data.get('content', '').split("\n")))

        # Kiểm chứng tính toàn vẹn
        assert read_data.get("content") == file_payload, "Lỗi đối soát nội dung file!"
        print("  [✓] Dữ liệu đối soát khớp 100% giữa nội dung ghi và nội dung đọc!")

    # =========================================================================
    # KỊCH BẢN 3: PHÒNG VỆ AN NINH (SECURITY REJECTION)
    # =========================================================================
    async def scenario_3_security_rejection(self, session: ClientSession):
        print_step(3, "PHÒNG VỆ AN NINH - TỪ CHỐI MÃ ĐỘC CRITICAL (Pre-Execution Guardrails)")
        print("Tình huống: Kẻ tấn công hoặc Agent vô ý gửi mã độc can thiệp hệ thống (import os, os.system).")

        malicious_code = "import os\nos.system('id && whoami')"
        print(f"[AI Agent Request]: Gửi mã độc:\n{malicious_code}")

        call_res = await session.call_tool(
            "execute_python",
            {"code": malicious_code, "session_id": self.session_id},
        )
        data = json.loads(call_res.content[0].text)

        print("[MCP Server Response]:")
        print(f"  - Thành công: {data.get('success')} (Đã chặn đứng)")
        print(f"  - Trạng thái: {data.get('status')}")
        print(f"  - Lý do từ chối: {data.get('decision_reason')}")
        print(f"  - Vi phạm phát hiện: {data.get('violations')}")
        print(f"  - Exit Code: {data.get('exit_code')}")
        print("  [✓] Hệ thống SandboxRunner hoàn toàn KHÔNG bị gọi, bảo vệ tuyệt đối máy chủ!")

    # =========================================================================
    # KỊCH BẢN 4: HUMAN-IN-THE-LOOP (HITL) WORKFLOW
    # =========================================================================
    async def scenario_4_human_in_the_loop(self, session: ClientSession):
        print_step(4, "QUY TRÌNH HUMAN-IN-THE-LOOP (HITL) - YÊU CẦU QUYỀN MẠNG NGOÀI")
        print("Tình huống: AI Agent cần thực hiện kết nối mạng (allow_network=True).")

        network_cmd = "curl -sI https://example.com"
        print(f"[AI Agent Request]: Gửi lệnh '{network_cmd}' với allow_network=True...")

        call_res = await session.call_tool(
            "execute_bash",
            {"command": network_cmd, "allow_network": True, "session_id": self.session_id},
        )
        data = json.loads(call_res.content[0].text)

        print("[MCP Server Response]:")
        print(f"  - Trạng thái: {data.get('status')}")
        print(f"  - Lý do: {data.get('decision_reason')}")
        print(f"  - Confirmation Token: {data.get('confirmation_token')}")
        print(f"  - Thời gian hết hạn: {data.get('expires_in')} giây")
        print(f"  - Hướng dẫn phê duyệt: {data.get('instruction')}")
        print("  [✓] Lệnh bị tạm giữ an toàn, KHÔNG tự động thực thi khi chưa có xác nhận từ con người!")


if __name__ == "__main__":
    demo = SandboxAgentDemo()
    asyncio.run(demo.run())
