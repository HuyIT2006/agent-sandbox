"""
mcp_server.py
Thành viên 2: Model Context Protocol (MCP) Server cho AGENT-SANDBOX
Cung cấp 4 công cụ chuẩn MCP (execute_bash, execute_python, read_workspace_file, write_workspace_file)
cho phép AI Agents giao tiếp và thực thi tác vụ an toàn trong Linux Sandbox.

Tuân thủ nghiêm ngặt:
- Mọi lệnh đều đi qua: CodeInspector -> PolicyEngine -> SessionManager -> HITL -> SandboxRunner.
- Không ghi log ra stdout (stdout dành riêng cho giao thức JSON-RPC của Stdio Transport).
- AI Agent không được cấp quyền tự phê duyệt confirmation_token.
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional

# Cấu hình logging hướng ra stderr để không làm hỏng kênh truyền stdout của MCP JSON-RPC
logger = logging.getLogger("agent_sandbox_mcp")
logger.setLevel(logging.INFO)
if not logger.handlers:
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [MCP] %(message)s"))
    logger.addHandler(stderr_handler)

# Import các thành phần cốt lõi đã hoàn thiện ở Giai đoạn 1 & 2
from gateway.inspector import CodeInspector
from gateway.policy import PolicyEngine
from gateway.session_manager import SessionManager
from gateway.api import (
    inspector as global_inspector,
    policy_engine as global_policy_engine,
    session_manager as global_session_manager,
    _dispatch_safe_execution,
)

# Thử import MCP SDK (hỗ trợ cả mcp 2.x và mcp 1.x)
try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as MCPServer
    except ImportError:
        MCPServer = None

# Giới hạn kích thước file an toàn
MAX_FILE_READ_BYTES = 5 * 1024 * 1024   # 5 MB
MAX_FILE_WRITE_BYTES = 10 * 1024 * 1024  # 10 MB


def create_mcp_server(
    inspector_instance: Optional[CodeInspector] = None,
    policy_instance: Optional[PolicyEngine] = None,
    session_instance: Optional[SessionManager] = None,
) -> Any:
    """Khởi tạo và cấu hình MCP Server với 4 công cụ cốt lõi."""
    if MCPServer is None:
        raise RuntimeError("Thư viện MCP SDK chưa được cài đặt!")

    inspector = inspector_instance or global_inspector
    policy_engine = policy_instance or global_policy_engine
    session_manager = session_instance or global_session_manager

    # Khởi tạo MCP Server với định danh hệ thống
    mcp = MCPServer(
        name="agent-sandbox",
        instructions="Secure Sandbox Environment for Agentic AI Tool Execution with Pre-Execution Guardrails and Linux Isolation.",
    )

    # =========================================================================
    # TOOL 1: execute_bash
    # =========================================================================
    @mcp.tool()
    def execute_bash(
        command: str,
        session_id: Optional[str] = None,
        allow_network: bool = False,
        timeout: int = 20,
    ) -> str:
        """
        Thực thi lệnh Bash trong Linux Sandbox có kiểm soát chính sách và cách ly kernel.

        Args:
            command: Câu lệnh Bash cần thực thi.
            session_id: ID phiên làm việc (để chia sẻ workspace).
            allow_network: Cho phép truy cập mạng (cần phê duyệt HITL nếu bật).
            timeout: Giới hạn thời gian chạy (giây, từ 1 đến 60).
        """
        if not command or not command.strip():
            return json.dumps({"success": False, "status": "ERROR", "error": "command không được để trống"}, ensure_ascii=False)

        timeout = max(1, min(60, timeout))

        # 1. Phân tích tĩnh cú pháp Bash qua AST bashlex
        inspect_res = inspector.inspect_bash(command)

        # 2. Đánh giá chính sách an toàn
        policy_res = policy_engine.evaluate(inspect_res, requested_network=allow_network)

        # Nếu rủi ro CRITICAL -> Từ chối ngay lập tức
        if policy_res["decision"] == "REJECT":
            logger.warning("MCP execute_bash REJECTED: %s", policy_res["reason"])
            return json.dumps({
                "success": False,
                "status": "REJECT",
                "decision_reason": policy_res["reason"],
                "violations": inspect_res.get("violations", []),
                "stderr": f"[Policy Block]: {policy_res['reason']}",
                "exit_code": 126,
            }, ensure_ascii=False)

        # Nếu cần phê duyệt từ con người -> Tạo pending approval HITL
        if policy_res["decision"] == "REQUIRE_CONFIRMATION":
            pending = policy_engine.create_pending_approval(
                tool_type="bash",
                code=command,
                session_id=session_id,
                allow_network=allow_network,
                timeout=timeout,
            )
            logger.info("MCP execute_bash REQUIRE_CONFIRMATION token=%s", pending.token)
            return json.dumps({
                "success": False,
                "status": "REQUIRE_CONFIRMATION",
                "decision_reason": policy_res["reason"],
                "confirmation_token": pending.token,
                "expires_in": int(pending.expires_at - pending.created_at),
                "instruction": "Hành động yêu cầu quyền nhạy cảm hoặc kết nối mạng. Hãy chuyển confirmation_token tới người vận hành có thẩm quyền phê duyệt qua REST API: POST /api/v1/confirm",
            }, ensure_ascii=False)

        # Nếu ALLOW -> Thực thi an toàn qua SandboxRunner
        exec_res = _dispatch_safe_execution(
            tool_type="bash",
            code=command,
            session_id=session_id,
            allow_network=allow_network,
            timeout=timeout,
            decision_reason=policy_res["reason"],
        )
        return json.dumps(exec_res.model_dump(), ensure_ascii=False)

    # =========================================================================
    # TOOL 2: execute_python
    # =========================================================================
    @mcp.tool()
    def execute_python(
        code: str,
        session_id: Optional[str] = None,
        allow_network: bool = False,
        timeout: int = 20,
    ) -> str:
        """
        Thực thi Python script an toàn trong Sandbox thông qua file tạm và kiểm soát AST.

        Args:
            code: Mã nguồn Python cần chạy.
            session_id: ID phiên làm việc.
            allow_network: Cho phép truy cập mạng (cần phê duyệt HITL nếu bật).
            timeout: Giới hạn thời gian chạy (giây, từ 1 đến 60).
        """
        if not code or not code.strip():
            return json.dumps({"success": False, "status": "ERROR", "error": "code không được để trống"}, ensure_ascii=False)

        timeout = max(1, min(60, timeout))

        # 1. Phân tích tĩnh cú pháp Python qua AST NodeVisitor
        inspect_res = inspector.inspect_python(code)

        # 2. Đánh giá chính sách an toàn
        policy_res = policy_engine.evaluate(inspect_res, requested_network=allow_network)

        # Nếu rủi ro CRITICAL -> REJECT
        if policy_res["decision"] == "REJECT":
            logger.warning("MCP execute_python REJECTED: %s", policy_res["reason"])
            return json.dumps({
                "success": False,
                "status": "REJECT",
                "decision_reason": policy_res["reason"],
                "violations": inspect_res.get("violations", []),
                "stderr": f"[Policy Block]: {policy_res['reason']}",
                "exit_code": 126,
            }, ensure_ascii=False)

        # Nếu cần phê duyệt HITL -> Sinh confirmation_token
        if policy_res["decision"] == "REQUIRE_CONFIRMATION":
            pending = policy_engine.create_pending_approval(
                tool_type="python",
                code=code,
                session_id=session_id,
                allow_network=allow_network,
                timeout=timeout,
            )
            logger.info("MCP execute_python REQUIRE_CONFIRMATION token=%s", pending.token)
            return json.dumps({
                "success": False,
                "status": "REQUIRE_CONFIRMATION",
                "decision_reason": policy_res["reason"],
                "confirmation_token": pending.token,
                "expires_in": int(pending.expires_at - pending.created_at),
                "instruction": "Script chứa thao tác rủi ro cao hoặc yêu cầu mạng. Hãy chuyển token tới người có thẩm quyền phê duyệt qua REST API: POST /api/v1/confirm",
            }, ensure_ascii=False)

        # Nếu ALLOW -> Thực thi an toàn (ghi script tạm UTF-8 vào workspace rồi gọi SandboxRunner)
        exec_res = _dispatch_safe_execution(
            tool_type="python",
            code=code,
            session_id=session_id,
            allow_network=allow_network,
            timeout=timeout,
            decision_reason=policy_res["reason"],
        )
        return json.dumps(exec_res.model_dump(), ensure_ascii=False)

    # =========================================================================
    # TOOL 3: read_workspace_file
    # =========================================================================
    @mcp.tool()
    def read_workspace_file(
        session_id: str,
        path: str,
    ) -> str:
        """
        Đọc nội dung tệp tin bên trong workspace của session cụ thể.
        Chặn tuyệt đối Path Traversal, đường dẫn tuyệt đối và symlink escape.

        Args:
            session_id: Định danh phiên làm việc.
            path: Đường dẫn tương đối của tệp tin bên trong workspace.
        """
        if not session_id or not session_id.strip():
            return json.dumps({"success": False, "error": "session_id không được để trống"}, ensure_ascii=False)
        if not path or not path.strip():
            return json.dumps({"success": False, "error": "path không được để trống"}, ensure_ascii=False)

        clean_path = path.strip()

        # 1. Từ chối đường dẫn tuyệt đối
        if os.path.isabs(clean_path) or clean_path.startswith("/") or clean_path.startswith("\\") or (len(clean_path) > 1 and clean_path[1] == ":"):
            return json.dumps({
                "success": False,
                "error": f"Không cho phép đường dẫn tuyệt đối: '{clean_path}'. Chỉ chấp nhận đường dẫn tương đối trong workspace."
            }, ensure_ascii=False)

        # 2. Chặn Path Traversal thô
        if ".." in clean_path.split("/") or ".." in clean_path.split("\\"):
            return json.dumps({
                "success": False,
                "error": "Phát hiện ký tự Path Traversal ('..') không được phép."
            }, ensure_ascii=False)

        try:
            # 3. Lấy thư mục workspace hợp lệ
            workspace_dir = session_manager.get_or_create_workspace(session_id)
            resolved_workspace = Path(workspace_dir).resolve()
            target_file = (resolved_workspace / clean_path).resolve()

            # 4. Xác minh đường dẫn nằm trong workspace
            try:
                target_file.relative_to(resolved_workspace)
            except ValueError:
                return json.dumps({"success": False, "error": "Đường dẫn file vượt ra ngoài phạm vi workspace."}, ensure_ascii=False)

            # 5. Kiểm tra symlink escape
            if (resolved_workspace / clean_path).is_symlink():
                real_target = (resolved_workspace / clean_path).resolve()
                try:
                    real_target.relative_to(resolved_workspace)
                except ValueError:
                    return json.dumps({"success": False, "error": "Symlink trỏ ra bên ngoài workspace bị cấm."}, ensure_ascii=False)

            # 6. Kiểm tra tồn tại
            if not target_file.exists():
                return json.dumps({"success": False, "error": f"File không tồn tại: '{clean_path}'"}, ensure_ascii=False)

            if not target_file.is_file():
                return json.dumps({"success": False, "error": f"Đường dẫn không phải là một tệp tin: '{clean_path}'"}, ensure_ascii=False)

            # 7. Kiểm tra kích thước file
            file_size = target_file.stat().st_size
            if file_size > MAX_FILE_READ_BYTES:
                return json.dumps({
                    "success": False,
                    "error": f"Kích thước file ({file_size} bytes) vượt quá giới hạn đọc tối đa ({MAX_FILE_READ_BYTES} bytes)."
                }, ensure_ascii=False)

            # 8. Đọc nội dung file UTF-8
            content = target_file.read_text(encoding="utf-8", errors="replace")

            return json.dumps({
                "success": True,
                "session_id": session_id,
                "path": clean_path,
                "size_bytes": file_size,
                "content": content,
            }, ensure_ascii=False)

        except Exception as e:
            logger.error("Lỗi khi đọc file %s: %s", clean_path, str(e))
            return json.dumps({"success": False, "error": f"Lỗi hệ thống khi đọc file: {str(e)}"}, ensure_ascii=False)

    # =========================================================================
    # TOOL 4: write_workspace_file
    # =========================================================================
    @mcp.tool()
    def write_workspace_file(
        session_id: str,
        path: str,
        content: str,
    ) -> str:
        """
        Ghi nội dung vào tệp tin bên trong workspace của session cụ thể.
        Chặn tuyệt đối Path Traversal, đường dẫn tuyệt đối và ghi đè file hệ thống ngoài workspace.

        Args:
            session_id: Định danh phiên làm việc.
            path: Đường dẫn tương đối của tệp tin bên trong workspace.
            content: Nội dung cần ghi vào tệp tin.
        """
        if not session_id or not session_id.strip():
            return json.dumps({"success": False, "error": "session_id không được để trống"}, ensure_ascii=False)
        if not path or not path.strip():
            return json.dumps({"success": False, "error": "path không được để trống"}, ensure_ascii=False)
        if content is None:
            return json.dumps({"success": False, "error": "content không được là null"}, ensure_ascii=False)

        clean_path = path.strip()

        # 1. Từ chối đường dẫn tuyệt đối
        if os.path.isabs(clean_path) or clean_path.startswith("/") or clean_path.startswith("\\") or (len(clean_path) > 1 and clean_path[1] == ":"):
            return json.dumps({
                "success": False,
                "error": f"Không cho phép đường dẫn tuyệt đối: '{clean_path}'. Chỉ chấp nhận đường dẫn tương đối trong workspace."
            }, ensure_ascii=False)

        # 2. Chặn Path Traversal thô
        if ".." in clean_path.split("/") or ".." in clean_path.split("\\"):
            return json.dumps({
                "success": False,
                "error": "Phát hiện ký tự Path Traversal ('..') không được phép."
            }, ensure_ascii=False)

        # 3. Giới hạn dung lượng ghi
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > MAX_FILE_WRITE_BYTES:
            return json.dumps({
                "success": False,
                "error": f"Kích thước nội dung ({len(content_bytes)} bytes) vượt quá giới hạn ghi tối đa ({MAX_FILE_WRITE_BYTES} bytes)."
            }, ensure_ascii=False)

        try:
            # 4. Lấy thư mục workspace
            workspace_dir = session_manager.get_or_create_workspace(session_id)
            resolved_workspace = Path(workspace_dir).resolve()
            target_file = (resolved_workspace / clean_path).resolve()

            # 5. Xác minh phạm vi an toàn
            try:
                target_file.relative_to(resolved_workspace)
            except ValueError:
                return json.dumps({"success": False, "error": "Đường dẫn file vượt ra ngoài phạm vi workspace."}, ensure_ascii=False)

            # 6. Kiểm tra symlink escape
            if target_file.exists() and target_file.is_symlink():
                real_target = target_file.resolve()
                try:
                    real_target.relative_to(resolved_workspace)
                except ValueError:
                    return json.dumps({"success": False, "error": "Không được ghi đè vào symlink trỏ ra bên ngoài workspace."}, ensure_ascii=False)

            # 7. Tạo thư mục cha nếu chưa có
            target_file.parent.mkdir(parents=True, exist_ok=True)

            # 8. Ghi nội dung an toàn UTF-8
            target_file.write_text(content, encoding="utf-8")

            return json.dumps({
                "success": True,
                "session_id": session_id,
                "path": clean_path,
                "bytes_written": len(content_bytes),
                "status": "SUCCESS",
            }, ensure_ascii=False)

        except Exception as e:
            logger.error("Lỗi khi ghi file %s: %s", clean_path, str(e))
            return json.dumps({"success": False, "error": f"Lỗi hệ thống khi ghi file: {str(e)}"}, ensure_ascii=False)

    return mcp


# Khởi tạo mặc định instance MCP Server cho Stdio Transport
mcp_server = create_mcp_server()


if __name__ == "__main__":
    # Khởi chạy Stdio Transport mặc định (tương tác qua stdin/stdout cho MCP Clients)
    import asyncio
    logger.info("Khởi chạy MCP Server (Stdio Transport)...")
    asyncio.run(mcp_server.run_stdio_async())
