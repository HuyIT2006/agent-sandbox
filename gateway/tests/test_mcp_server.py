"""
test_mcp_server.py
Bộ Unit Test toàn diện cho Giai đoạn 3 - Nhiệm vụ 2 (Thành viên 2)
Kiểm thử Model Context Protocol (MCP) Server:
- MCP Protocol (Khởi tạo, list_tools, call_tool).
- 4 Tools cốt lõi: execute_bash, execute_python, read_workspace_file, write_workspace_file.
- Phòng vệ Path Traversal, Absolute Path, File size limit.
- Tích hợp Dynamic Policy Engine & HITL confirmation workflow từ MCP sang REST API.
"""

import asyncio
import json
import shutil
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Thêm thư mục gốc vào sys.path
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gateway.mcp_server import create_mcp_server, mcp_server
from gateway.policy import PolicyEngine
from gateway.inspector import CodeInspector
from gateway.session_manager import SessionManager
from gateway.api import ConfirmRequest, confirm_execution


# =====================================================================
# NHÓM 1: MCP PROTOCOL & TOOL DISCOVERY
# =====================================================================
class TestMCPProtocol(unittest.IsolatedAsyncioTestCase):
    """Kiểm thử tầng giao thức MCP: khởi tạo server, liệt kê công cụ và gọi công cụ."""

    async def asyncSetUp(self):
        self.server = mcp_server

    async def test_01_server_initialization_and_tool_discovery(self):
        """tools/list trả về chính xác 4 công cụ chuẩn của hệ thống."""
        tools = await self.server.list_tools()
        tool_names = [t.name for t in tools]

        self.assertEqual(len(tool_names), 4)
        self.assertIn("execute_bash", tool_names)
        self.assertIn("execute_python", tool_names)
        self.assertIn("read_workspace_file", tool_names)
        self.assertIn("write_workspace_file", tool_names)

    async def test_02_call_tool_invalid_parameters_fail_safe(self):
        """Gọi tool với tham số rỗng hoặc thiếu phải trả về lỗi có cấu trúc, không làm sập server."""
        # Gọi execute_bash với command rỗng
        res_bash = await self.server.call_tool("execute_bash", {"command": ""})
        # Lấy nội dung text từ response content
        data = json.loads(res_bash.content[0].text)
        self.assertFalse(data["success"])
        self.assertIn("không được để trống", data.get("error", ""))

        # Gọi read_workspace_file với path rỗng
        res_file = await self.server.call_tool("read_workspace_file", {"session_id": "s1", "path": ""})
        data_file = json.loads(res_file.content[0].text)
        self.assertFalse(data_file["success"])
        self.assertIn("không được để trống", data_file.get("error", ""))


# =====================================================================
# NHÓM 2: TOOL execute_bash
# =====================================================================
class TestMCPExecuteBash(unittest.IsolatedAsyncioTestCase):
    """Kiểm thử công cụ execute_bash qua MCP."""

    @patch("gateway.api.runner.execute")
    async def test_01_execute_safe_bash_allow(self, mock_runner_exec):
        """Lệnh Bash an toàn được ALLOW và thực thi qua SandboxRunner."""
        mock_runner_exec.return_value = {
            "stdout": "total 0\n-rw-r--r-- 1 root root 0 test.txt",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 12,
            "sandbox_id": "sbx_bash_ok",
        }
        res = await mcp_server.call_tool("execute_bash", {"command": "ls -la"})
        data = json.loads(res.content[0].text)

        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "EXECUTED")
        self.assertIn("test.txt", data["stdout"])
        mock_runner_exec.assert_called_once()

    @patch("gateway.api.runner.execute")
    async def test_02_execute_dangerous_bash_reject(self, mock_runner_exec):
        """Lệnh Bash nguy hiểm bị REJECT và KHÔNG gọi runner."""
        res = await mcp_server.call_tool("execute_bash", {"command": "rm -rf /"})
        data = json.loads(res.content[0].text)

        self.assertFalse(data["success"])
        self.assertEqual(data["status"], "REJECT")
        self.assertIn("CRITICAL", data["decision_reason"])
        mock_runner_exec.assert_not_called()

    @patch("gateway.api.runner.execute")
    async def test_03_execute_bash_require_confirmation(self, mock_runner_exec):
        """Yêu cầu quyền mạng ngoài trả về confirmation_token và hướng dẫn HITL."""
        res = await mcp_server.call_tool(
            "execute_bash",
            {"command": "curl http://external.api", "allow_network": True},
        )
        data = json.loads(res.content[0].text)

        self.assertFalse(data["success"])
        self.assertEqual(data["status"], "REQUIRE_CONFIRMATION")
        self.assertIn("confirmation_token", data)
        self.assertTrue(len(data["confirmation_token"]) >= 32)
        mock_runner_exec.assert_not_called()


# =====================================================================
# NHÓM 3: TOOL execute_python
# =====================================================================
class TestMCPExecutePython(unittest.IsolatedAsyncioTestCase):
    """Kiểm thử công cụ execute_python qua MCP."""

    @patch("gateway.api.runner.execute")
    async def test_01_execute_safe_python_allow(self, mock_runner_exec):
        """Script Python an toàn được ghi vào workspace và thực thi qua SandboxRunner."""
        mock_runner_exec.return_value = {
            "stdout": "42\n",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 15,
            "sandbox_id": "sbx_py_ok",
        }
        py_code = "a = 40\nb = 2\nprint(a + b)"
        res = await mcp_server.call_tool("execute_python", {"code": py_code})
        data = json.loads(res.content[0].text)

        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "EXECUTED")
        mock_runner_exec.assert_called_once()

    @patch("gateway.api.runner.execute")
    async def test_02_execute_dangerous_python_reject(self, mock_runner_exec):
        """Script Python nguy hiểm bị REJECT và KHÔNG gọi runner."""
        malicious_code = "import os\nos.system('whoami')"
        res = await mcp_server.call_tool("execute_python", {"code": malicious_code})
        data = json.loads(res.content[0].text)

        self.assertFalse(data["success"])
        self.assertEqual(data["status"], "REJECT")
        mock_runner_exec.assert_not_called()

    @patch("gateway.api.runner.execute")
    async def test_03_execute_python_multiline_and_unicode(self, mock_runner_exec):
        """Mã Python nhiều dòng và tiếng Việt có dấu được truyền an toàn."""
        captured_cmd = None

        def fake_exec(command, workspace_dir=None, network_enabled=False, timeout=None):
            nonlocal captured_cmd
            captured_cmd = command
            return {"stdout": "Tiếng Việt OK", "stderr": "", "exit_code": 0, "duration_ms": 10, "sandbox_id": "sbx_uni"}

        mock_runner_exec.side_effect = fake_exec

        code_vi = 'msg = "Xin chào AI Agent từ MCP!"\nprint(msg)'
        res = await mcp_server.call_tool("execute_python", {"code": code_vi})
        data = json.loads(res.content[0].text)

        self.assertTrue(data["success"])
        self.assertTrue(captured_cmd.startswith("python3 _task_"))


# =====================================================================
# NHÓM 4: WORKSPACE FILE TOOLS (read & write)
# =====================================================================
class TestMCPFileTools(unittest.IsolatedAsyncioTestCase):
    """Kiểm thử read_workspace_file và write_workspace_file kèm các cơ chế phòng thủ."""

    async def asyncSetUp(self):
        self.session_id = "test_mcp_file_sess"

    async def asyncTearDown(self):
        # Dọn dẹp thư mục sau test
        from gateway.session_manager import BASE_WORKSPACE_DIR
        target = BASE_WORKSPACE_DIR / self.session_id
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)

    async def test_01_write_and_read_valid_file(self):
        """Ghi và đọc lại file hợp lệ trong workspace bằng UTF-8."""
        content = "Xin chào, đây là file cấu hình thử nghiệm!\nLine 2: 12345"
        rel_path = "configs/settings.json"

        # 1. Ghi file
        res_write = await mcp_server.call_tool(
            "write_workspace_file",
            {"session_id": self.session_id, "path": rel_path, "content": content},
        )
        write_data = json.loads(res_write.content[0].text)
        self.assertTrue(write_data["success"])
        self.assertEqual(write_data["status"], "SUCCESS")

        # 2. Đọc file
        res_read = await mcp_server.call_tool(
            "read_workspace_file",
            {"session_id": self.session_id, "path": rel_path},
        )
        read_data = json.loads(res_read.content[0].text)
        self.assertTrue(read_data["success"])
        self.assertEqual(read_data["content"], content)

    async def test_02_prevent_path_traversal(self):
        """Chặn hoàn toàn các nỗ lực Path Traversal (../)."""
        malicious_paths = [
            "../../etc/passwd",
            "sub/../../secret.txt",
            "..\\..\\windows\\win.ini",
        ]
        for p in malicious_paths:
            res = await mcp_server.call_tool(
                "read_workspace_file",
                {"session_id": self.session_id, "path": p},
            )
            data = json.loads(res.content[0].text)
            self.assertFalse(data["success"])
            self.assertIn("Path Traversal", data["error"])

    async def test_03_prevent_absolute_paths(self):
        """Từ chối mọi đường dẫn tuyệt đối bắt đầu bằng / hoặc ổ đĩa."""
        abs_paths = [
            "/etc/shadow",
            "/var/log/syslog",
            "C:\\Windows\\System32\\cmd.exe",
        ]
        for p in abs_paths:
            res = await mcp_server.call_tool(
                "write_workspace_file",
                {"session_id": self.session_id, "path": p, "content": "bad"},
            )
            data = json.loads(res.content[0].text)
            self.assertFalse(data["success"])
            self.assertIn("tuyệt đối", data["error"])

    async def test_04_read_non_existent_file(self):
        """Đọc file không tồn tại trả về thông báo lỗi rõ ràng."""
        res = await mcp_server.call_tool(
            "read_workspace_file",
            {"session_id": self.session_id, "path": "not_found.txt"},
        )
        data = json.loads(res.content[0].text)
        self.assertFalse(data["success"])
        self.assertIn("không tồn tại", data["error"])


# =====================================================================
# NHÓM 5: TÍCH HỢP POLICY VÀ HITL WORKFLOW (MCP -> REST API)
# =====================================================================
class TestMCPPolicyHITLIntegration(unittest.IsolatedAsyncioTestCase):
    """
    Kiểm thử luồng phối hợp hoàn chỉnh:
    1. AI Agent gọi MCP execute_bash với cờ allow_network=True.
    2. MCP Server trả về confirmation_token (không thực thi ngay).
    3. Người có thẩm quyền phê duyệt token qua REST API POST /api/v1/confirm.
    4. SandboxRunner được gọi thực thi đúng một lần với payload gốc.
    """

    @patch("gateway.api.runner.execute")
    async def test_01_mcp_hitl_end_to_end_approval(self, mock_runner_exec):
        mock_runner_exec.return_value = {
            "stdout": "Connected to network host",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 30,
            "sandbox_id": "sbx_mcp_hitl",
        }

        # Bước 1: AI Agent gọi qua MCP
        res = await mcp_server.call_tool(
            "execute_bash",
            {"command": "curl http://external.service", "allow_network": True, "session_id": "sess_hitl_e2e"},
        )
        mcp_data = json.loads(res.content[0].text)
        self.assertEqual(mcp_data["status"], "REQUIRE_CONFIRMATION")
        token = mcp_data["confirmation_token"]
        self.assertIsNotNone(token)

        # Runner chưa được gọi
        mock_runner_exec.assert_not_called()

        # Bước 2: Người quản trị phê duyệt qua REST API confirm_execution
        req_confirm = ConfirmRequest(confirmation_token=token, decision="APPROVED")
        confirm_resp = confirm_execution(req_confirm)

        self.assertTrue(confirm_resp.success)
        self.assertEqual(confirm_resp.status, "EXECUTED")
        mock_runner_exec.assert_called_once()

        # Bước 3: Xác minh token không thể dùng lại lần 2
        req_replay = ConfirmRequest(confirmation_token=token, decision="APPROVED")
        with self.assertRaises(Exception):
            confirm_execution(req_replay)


if __name__ == "__main__":
    print("==============================================================")
    print("   RUNNING GATEWAY PHASE 3 MCP SERVER UNIT TEST SUITE         ")
    print("==============================================================")
    unittest.main()
