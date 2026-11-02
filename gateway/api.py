"""
api.py
Thành viên 2: Tool Execution API Gateway (FastAPI)
Cung cấp endpoint cho AI Agent gửi yêu cầu chạy mã lệnh trong Sandbox.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

from core.runner import SandboxRunner
from gateway.inspector import CodeInspector
from gateway.policy import PolicyEngine
from gateway.session_manager import SessionManager

app = FastAPI(
    title="Secure Agentic AI Sandbox API",
    description="API Gateway an toàn thực thi công cụ Bash và Python cho AI Agents",
    version="1.0.0",
)

runner = SandboxRunner()
inspector = CodeInspector()
policy_engine = PolicyEngine()
session_manager = SessionManager()


class ExecuteRequest(BaseModel):
    tool_type: str = Field(..., description="'bash' hoặc 'python'")
    code: str = Field(..., description="Lệnh bash hoặc script python cần chạy")
    session_id: Optional[str] = Field(None, description="ID phiên làm việc (stateful workspace)")
    allow_network: bool = Field(False, description="Cho phép kết nối mạng (cần phê duyệt)")
    timeout: Optional[int] = Field(20, ge=1, le=60, description="Thời gian chạy tối đa (giây)")


class ExecuteResponse(BaseModel):
    success: bool
    status: str
    decision_reason: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: int = 0
    sandbox_id: Optional[str] = None


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "agent-sandbox-gateway"}


@app.post("/api/v1/execute", response_model=ExecuteResponse)
def execute_tool(req: ExecuteRequest):
    # 1. Phân tích tĩnh cú pháp
    if req.tool_type.lower() == "python":
        inspect_res = inspector.inspect_python(req.code)
        # Bọc code Python để thực thi qua python3 -c trong sandbox
        escaped_code = req.code.replace('"', '\\"')
        exec_cmd = f'python3 -c "{escaped_code}"'
    elif req.tool_type.lower() == "bash":
        inspect_res = inspector.inspect_bash(req.code)
        exec_cmd = req.code
    else:
        raise HTTPException(status_code=400, detail="tool_type chỉ hỗ trợ 'bash' hoặc 'python'")

    # 2. Đánh giá chính sách an toàn
    policy_res = policy_engine.evaluate(inspect_res, requested_network=req.allow_network)
    if not policy_res["can_proceed"]:
        return ExecuteResponse(
            success=False,
            status=policy_res["decision"],
            decision_reason=policy_res["reason"],
            stderr=f"[Policy Block]: {policy_res['reason']}",
            exit_code=126,
        )

    # 3. Lấy hoặc tạo workspace cho session
    workspace_dir = None
    if req.session_id:
        workspace_dir = session_manager.get_or_create_workspace(req.session_id)

    # 4. Gửi sang Core Sandbox để thực thi
    run_res = runner.execute(
        command=exec_cmd,
        workspace_dir=workspace_dir,
        network_enabled=req.allow_network,
        timeout=req.timeout,
    )

    return ExecuteResponse(
        success=(run_res["exit_code"] == 0),
        status="EXECUTED",
        decision_reason=policy_res["reason"],
        stdout=run_res["stdout"],
        stderr=run_res["stderr"],
        exit_code=run_res["exit_code"],
        duration_ms=run_res["duration_ms"],
        sandbox_id=run_res["sandbox_id"],
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway.api:app", host="0.0.0.0", port=8000, reload=True)
