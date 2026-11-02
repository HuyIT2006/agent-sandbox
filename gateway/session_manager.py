"""
session_manager.py
Thành viên 2: Quản lý Phiên làm việc và Thư mục Workspace tạm thời
"""

import shutil
import time
from pathlib import Path
from typing import Dict, Optional

BASE_WORKSPACE_DIR = Path("/tmp/agent_workspaces")


class SessionManager:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl_seconds = ttl_seconds
        self.sessions: Dict[str, Dict[str, Any]] = {}
        BASE_WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

    def get_or_create_workspace(self, session_id: str) -> str:
        """Lấy hoặc tạo thư mục workspace cho phiên làm việc."""
        ws_path = BASE_WORKSPACE_DIR / session_id
        ws_path.mkdir(parents=True, exist_ok=True)

        self.sessions[session_id] = {
            "path": str(ws_path),
            "last_active": time.time(),
        }
        return str(ws_path)

    def cleanup_session(self, session_id: str):
        """Xóa sạch thư mục workspace khi kết thúc phiên."""
        if session_id in self.sessions:
            ws_path = Path(self.sessions[session_id]["path"])
            if ws_path.exists():
                shutil.rmtree(ws_path, ignore_errors=True)
            del self.sessions[session_id]

    def cleanup_expired(self):
        """Dọn dẹp các session đã hết hạn."""
        now = time.time()
        expired = [
            sid for sid, data in self.sessions.items()
            if now - data["last_active"] > self.ttl_seconds
        ]
        for sid in expired:
            self.cleanup_session(sid)
