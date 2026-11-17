"""
api.py
Thành viên 2: Tool Execution API Gateway (FastAPI) tích hợp Dynamic Policy Engine & Human-in-the-Loop (HITL)
Cung cấp endpoint an toàn cho AI Agent gửi yêu cầu chạy mã lệnh trong Sandbox và cơ chế xác thực phê duyệt con người.
"""

import os
import shlex
import uuid
from pathlib import Path
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from core.runner import SandboxRunner
from gateway.inspector import CodeInspector
from gateway.policy import PolicyEngine
from gateway.session_manager import SessionManager

app = FastAPI(
    title="Secure Agentic AI Sandbox API",
    description="API Gateway an toàn thực thi công cụ Bash và Python cho AI Agents kèm HITL Approval Workflow",
    version="1.0.0",
)

try:
    runner = SandboxRunner()
except Exception:
    # Khi chạy trên môi trường chưa có bwrap (ví dụ Windows dev/test),
    # giữ runner dưới dạng placeholder an toàn để cho phép mock trong unit test
    class _UnavailableRunner:
        def execute(self, *args, **kwargs):
            raise RuntimeError("Lỗi: 'bwrap' (Bubblewrap) chưa được cài đặt trên hệ thống này!")
    runner = _UnavailableRunner()

inspector = CodeInspector()
policy_engine = PolicyEngine()
session_manager = SessionManager()


# =============================================================================
# MODELS
# =============================================================================
class ExecuteRequest(BaseModel):
    tool_type: str = Field(..., description="'bash' hoặc 'python'")
    code: str = Field(..., description="Lệnh bash hoặc script python cần chạy")
    session_id: Optional[str] = Field(None, description="ID phiên làm việc (stateful workspace)")
    allow_network: bool = Field(False, description="Cho phép kết nối mạng (cần phê duyệt)")
    timeout: Optional[int] = Field(20, ge=1, le=60, description="Thời gian chạy tối đa (giây)")


class ConfirmRequest(BaseModel):
    confirmation_token: str = Field(..., description="Confirmation token đã được cấp khi yêu cầu cần HITL")
    decision: str = Field(..., description="Quyết định phê duyệt: 'APPROVED' hoặc 'REJECTED'")


class ExecuteResponse(BaseModel):
    success: bool
    status: str
    decision_reason: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: int = 0
    sandbox_id: Optional[str] = None
    confirmation_token: Optional[str] = None
    expires_in: Optional[int] = None


# =============================================================================
# HELPER THỰC THI AN TOÀN TRONG SANDBOX
# =============================================================================
def _dispatch_safe_execution(
    tool_type: str,
    code: str,
    session_id: Optional[str],
    allow_network: bool,
    timeout: Optional[int],
    decision_reason: str,
) -> ExecuteResponse:
    """Thực thi mã nguồn an toàn qua SandboxRunner với workspace và script file tạm thời."""
    is_ephemeral_session = False
    ephemeral_sid = None

    if session_id:
        workspace_dir = session_manager.get_or_create_workspace(session_id)
    else:
        ephemeral_sid = f"ephemeral_{uuid.uuid4().hex[:12]}"
        workspace_dir = session_manager.get_or_create_workspace(ephemeral_sid)
        is_ephemeral_session = True

    resolved_workspace = Path(workspace_dir).resolve()
    temp_script_path: Optional[Path] = None

    try:
        if tool_type == "python":
            script_filename = f"_task_{uuid.uuid4().hex}.py"
            temp_script_path = (resolved_workspace / script_filename).resolve()

            try:
                temp_script_path.relative_to(resolved_workspace)
            except ValueError:
                raise HTTPException(status_code=400, detail="Đường dẫn script không hợp lệ bên ngoài workspace")

            temp_script_path.write_text(code, encoding="utf-8")
            exec_cmd = f"python3 {shlex.quote(script_filename)}"
        else:
            exec_cmd = code

        try:
            run_res = runner.execute(
                command=exec_cmd,
                workspace_dir=str(resolved_workspace),
                network_enabled=allow_network,
                timeout=timeout,
            )
        except Exception as e:
            run_res = {
                "stdout": "",
                "stderr": f"[Runner Execution Error]: {str(e)}",
                "exit_code": 1,
                "duration_ms": 0,
                "sandbox_id": None,
            }


        return ExecuteResponse(
            success=(run_res.get("exit_code", 1) == 0),
            status="EXECUTED",
            decision_reason=decision_reason,
            stdout=run_res.get("stdout", ""),
            stderr=run_res.get("stderr", ""),
            exit_code=run_res.get("exit_code", 0),
            duration_ms=run_res.get("duration_ms", 0),
            sandbox_id=run_res.get("sandbox_id"),
        )

    finally:
        if temp_script_path and temp_script_path.exists():
            try:
                temp_script_path.unlink()
            except Exception:
                pass

        if is_ephemeral_session and ephemeral_sid:
            try:
                session_manager.cleanup_session(ephemeral_sid)
            except Exception:
                pass


# =============================================================================
# ENDPOINTS
# =============================================================================
@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "agent-sandbox-gateway",
        "session_backend": session_manager.backend_type,
    }


@app.post("/api/v1/execute", response_model=ExecuteResponse)
def execute_tool(req: ExecuteRequest):
    normalized_tool = req.tool_type.strip().lower()
    if normalized_tool not in ("bash", "python"):
        raise HTTPException(status_code=400, detail="tool_type chỉ hỗ trợ 'bash' hoặc 'python'")

    # 1. Phân tích tĩnh cú pháp (Static AST / Command Inspection)
    if normalized_tool == "python":
        inspect_res = inspector.inspect_python(req.code)
    else:
        inspect_res = inspector.inspect_bash(req.code)

    # 2. Đánh giá chính sách an toàn (Dynamic Policy Engine)
    policy_res = policy_engine.evaluate(inspect_res, requested_network=req.allow_network)

    # Nếu rủi ro CRITICAL hoặc bị cấm bởi Denylist -> REJECT
    if policy_res["decision"] == "REJECT":
        return ExecuteResponse(
            success=False,
            status="REJECT",
            decision_reason=policy_res["reason"],
            stderr=f"[Policy Block]: {policy_res['reason']}",
            exit_code=126,
        )

    # Nếu yêu cầu cần xác nhận từ con người -> REQUIRE_CONFIRMATION (HITL)
    if policy_res["decision"] == "REQUIRE_CONFIRMATION":
        pending = policy_engine.create_pending_approval(
            tool_type=normalized_tool,
            code=req.code,
            session_id=req.session_id,
            allow_network=req.allow_network,
            timeout=req.timeout or 20,
        )
        return ExecuteResponse(
            success=False,
            status="REQUIRE_CONFIRMATION",
            decision_reason=policy_res["reason"],
            stderr=f"[Policy HITL]: {policy_res['reason']} (Vui lòng sử dụng token để xác nhận tại /api/v1/confirm)",
            exit_code=126,
            confirmation_token=pending.token,
            expires_in=int(pending.expires_at - pending.created_at),
        )

    # Nếu ALLOW -> Thực thi ngay qua SandboxRunner
    return _dispatch_safe_execution(
        tool_type=normalized_tool,
        code=req.code,
        session_id=req.session_id,
        allow_network=req.allow_network,
        timeout=req.timeout,
        decision_reason=policy_res["reason"],
    )


@app.post("/api/v1/confirm", response_model=ExecuteResponse)
def confirm_execution(req: ConfirmRequest):
    """
    Endpoint phê duyệt Human-in-the-Loop (HITL):
    - Xác thực token và trạng thái pending nguyên tử (atomic).
    - Lấy nguyên bản payload đã lưu ban đầu, không nhận code từ client.
    - Đánh giá lại an toàn (không cho phép APPROVED vượt qua rủi ro CRITICAL).
    - Thực thi qua SandboxRunner nếu APPROVED.
    """
    normalized_decision = req.decision.strip().upper()
    if normalized_decision not in ("APPROVED", "REJECTED"):
        raise HTTPException(status_code=400, detail="Quyết định chỉ chấp nhận 'APPROVED' hoặc 'REJECTED'")

    # Kiểm tra trước trạng thái token để trả mã lỗi HTTP tương ứng
    existing_approval = policy_engine.get_pending_approval(req.confirmation_token)
    if not existing_approval:
        raise HTTPException(status_code=404, detail="Confirmation token không tồn tại hoặc không hợp lệ")

    if existing_approval.is_expired():
        raise HTTPException(status_code=410, detail="Confirmation token đã hết hạn")

    if existing_approval.status in ("CONSUMED", "REJECTED"):
        raise HTTPException(status_code=409, detail=f"Confirmation token đã được xử lý trước đó ({existing_approval.status})")

    # Giải quyết token nguyên tử (atomic)
    success, err_msg, approval = policy_engine.resolve_pending_approval(
        token=req.confirmation_token,
        decision=normalized_decision,
    )
    if not success or not approval:
        raise HTTPException(status_code=400, detail=err_msg or "Xác nhận token thất bại")

    # Trường hợp người vận hành từ chối (REJECTED)
    if normalized_decision == "REJECTED":
        return ExecuteResponse(
            success=False,
            status="REJECTED",
            decision_reason="Yêu cầu thực thi đã bị từ chối bởi Human-in-the-Loop",
            stderr="[HITL]: Yêu cầu bị người quản trị từ chối phê duyệt.",
            exit_code=126,
        )

    # Trường hợp người vận hành phê duyệt (APPROVED)
    # Lấy payload ban đầu đã lưu
    orig_tool_type = approval.tool_type
    orig_code = approval.code
    orig_session_id = approval.session_id
    orig_network = approval.allow_network
    orig_timeout = approval.timeout

    # Đánh giá lại mã nguồn để đảm bảo tuyệt đối không bypass rủi ro CRITICAL
    if orig_tool_type == "python":
        re_inspect = inspector.inspect_python(orig_code)
    else:
        re_inspect = inspector.inspect_bash(orig_code)

    if re_inspect.get("risk_level") == "CRITICAL":
        return ExecuteResponse(
            success=False,
            status="REJECT",
            decision_reason="Phát hiện rủi ro mức độ CRITICAL trong mã nguồn. Quyết định Human Approval không được phép vượt qua các quy tắc REJECT bắt buộc.",
            stderr="[Policy Block]: Không thể thực thi mã mức độ CRITICAL ngay cả khi có phê duyệt.",
            exit_code=126,
        )

    # Thực thi an toàn với payload ban đầu
    return _dispatch_safe_execution(
        tool_type=orig_tool_type,
        code=orig_code,
        session_id=orig_session_id,
        allow_network=orig_network,
        timeout=orig_timeout,
        decision_reason="Được phê duyệt thực thi bởi Human-in-the-Loop (HITL)",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway.api:app", host="0.0.0.0", port=8000, reload=True)
