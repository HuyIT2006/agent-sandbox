"""
session_manager.py
Thành viên 2: Quản lý Phiên làm việc (Session Manager) tích hợp Redis TTL & In-memory Fallback
Hỗ trợ lưu trữ trạng thái phiên làm việc, gia hạn TTL, dọn dẹp workspace tạm an toàn và chống Path Traversal.
"""

import json
import logging
import os
import re
import shutil
import threading
import time
from pathlib import Path
from typing import Dict, Any, Optional, List

logger = logging.getLogger("gateway.session_manager")

# Thư mục gốc chứa workspace tạm cho các session
BASE_WORKSPACE_DIR = Path("/tmp/agent_workspaces")

# Định dạng session_id an toàn (chỉ chứa chữ cái, số, gạch dưới, gạch ngang)
SAFE_SESSION_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]+$")


class SessionManager:
    """
    Quản lý vòng đời phiên (Session Lifecycle) và Workspace:
    - Lưu metadata vào Redis với TTL tự động nếu Redis sẵn sàng.
    - Tự động chuyển đổi sang In-memory Fallback (thread-safe) khi Redis offline.
    - Bảo vệ chống Path Traversal và làm sạch thư mục đĩa an toàn.
    """

    def __init__(
        self,
        ttl_seconds: int = 3600,
        redis_url: Optional[str] = None,
        base_dir: Optional[Path] = None,
    ):
        self.ttl_seconds = ttl_seconds
        self.base_dir = (base_dir or BASE_WORKSPACE_DIR).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

        # Trạng thái Backend
        self.redis_client = None
        self.is_redis_active = False
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")

        # In-memory storage & Lock cho Fallback mode
        self._memory_sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

        # Thử kết nối Redis
        self._init_redis()

    def _init_redis(self):
        """Khởi tạo và kiểm tra kết nối tới Redis với timeout ngắn, không làm crash hệ thống."""
        try:
            import redis
            client = redis.Redis.from_url(
                self.redis_url,
                socket_connect_timeout=2.0,
                socket_timeout=2.0,
                decode_responses=True,
            )
            # Health check ping
            client.ping()
            self.redis_client = client
            self.is_redis_active = True
            logger.info("SessionManager đã kết nối thành công tới Redis: %s", self.redis_url)
        except Exception as e:
            self.redis_client = None
            self.is_redis_active = False
            logger.warning(
                "Redis không khả dụng (%s). SessionManager tự động kích hoạt In-memory Fallback mode.",
                str(e),
            )

    @property
    def backend_type(self) -> str:
        """Trả về kiểu backend đang hoạt động thực tế: 'REDIS' hoặc 'IN_MEMORY'."""
        return "REDIS" if self.is_redis_active else "IN_MEMORY"

    def _validate_session_id(self, session_id: str):
        """Xác thực định danh session_id hợp lệ, ngăn chặn Path Traversal."""
        if not session_id or not isinstance(session_id, str):
            raise ValueError("session_id không được để trống")
        if not SAFE_SESSION_ID_REGEX.match(session_id):
            raise ValueError(
                f"session_id chứa ký tự không an toàn hoặc có dấu hiệu Path Traversal: '{session_id}'"
            )

    def _get_redis_key(self, session_id: str) -> str:
        return f"agent_sandbox:session:{session_id}"

    # =========================================================================
    # CORE API: GET HOẶC TẠO WORKSPACE
    # =========================================================================
    def get_or_create_workspace(self, session_id: str) -> str:
        """Lấy hoặc tạo mới thư mục workspace cho phiên làm việc."""
        self._validate_session_id(session_id)

        ws_path = (self.base_dir / session_id).resolve()

        # Kiểm tra an toàn: đường dẫn workspace bắt buộc phải nằm bên trong base_dir
        try:
            ws_path.relative_to(self.base_dir)
        except ValueError:
            raise ValueError(f"Đường dẫn workspace vi phạm phạm vi gốc: {ws_path}")

        ws_path.mkdir(parents=True, exist_ok=True)
        now = time.time()

        # 1. Nếu đang dùng Redis Backend
        if self.is_redis_active and self.redis_client:
            try:
                key = self._get_redis_key(session_id)
                session_data = {
                    "session_id": session_id,
                    "path": str(ws_path),
                    "last_active": now,
                    "status": "ACTIVE",
                }
                # Lưu metadata dạng JSON và đặt TTL
                self.redis_client.set(key, json.dumps(session_data), ex=self.ttl_seconds)
                return str(ws_path)
            except Exception as e:
                logger.warning("Thao tác Redis thất bại (%s), fallback sang in-memory", str(e))
                self.is_redis_active = False

        # 2. Fallback sang In-memory Backend
        with self._lock:
            self._memory_sessions[session_id] = {
                "session_id": session_id,
                "path": str(ws_path),
                "last_active": now,
                "status": "ACTIVE",
            }

        return str(ws_path)

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Lấy metadata của session."""
        self._validate_session_id(session_id)

        if self.is_redis_active and self.redis_client:
            try:
                key = self._get_redis_key(session_id)
                raw = self.redis_client.get(key)
                if raw:
                    return json.loads(raw)
                return None
            except Exception:
                self.is_redis_active = False

        with self._lock:
            data = self._memory_sessions.get(session_id)
            if not data:
                return None
            if time.time() - data["last_active"] > self.ttl_seconds:
                return None
            return dict(data)

    def touch_session(self, session_id: str) -> bool:
        """Gia hạn TTL cho session khi có hoạt động mới."""
        self._validate_session_id(session_id)
        now = time.time()

        if self.is_redis_active and self.redis_client:
            try:
                key = self._get_redis_key(session_id)
                raw = self.redis_client.get(key)
                if raw:
                    data = json.loads(raw)
                    data["last_active"] = now
                    self.redis_client.set(key, json.dumps(data), ex=self.ttl_seconds)
                    return True
                return False
            except Exception:
                self.is_redis_active = False

        with self._lock:
            if session_id in self._memory_sessions:
                self._memory_sessions[session_id]["last_active"] = now
                return True
        return False

    # =========================================================================
    # DỌN DẸP SESSION VÀ WORKSPACE
    # =========================================================================
    def cleanup_session(self, session_id: str):
        """Xóa sạch thư mục workspace trên đĩa và xóa metadata khi kết thúc phiên."""
        self._validate_session_id(session_id)
        ws_path = (self.base_dir / session_id).resolve()

        # Đảm bảo chỉ xóa thư mục nằm bên trong base_dir
        if ws_path.exists():
            try:
                ws_path.relative_to(self.base_dir)
                if ws_path != self.base_dir:
                    shutil.rmtree(ws_path, ignore_errors=True)
            except Exception as e:
                logger.error("Lỗi khi xóa workspace %s: %s", ws_path, str(e))

        # Xóa metadata trong Redis
        if self.is_redis_active and self.redis_client:
            try:
                self.redis_client.delete(self._get_redis_key(session_id))
            except Exception:
                pass

        # Xóa metadata trong in-memory
        with self._lock:
            if session_id in self._memory_sessions:
                del self._memory_sessions[session_id]

    def cleanup_expired(self):
        """Dọn dẹp các session đã hết hạn cả trên metadata và filesystem."""
        now = time.time()

        # Dọn dẹp trong In-memory
        with self._lock:
            expired = [
                sid for sid, data in self._memory_sessions.items()
                if now - data["last_active"] > self.ttl_seconds
            ]
        for sid in expired:
            self.cleanup_session(sid)

        # Dọn dẹp trong Redis (nếu có key prefix)
        if self.is_redis_active and self.redis_client:
            try:
                keys = self.redis_client.keys("agent_sandbox:session:*")
                for k in keys:
                    ttl = self.redis_client.ttl(k)
                    if ttl is not None and ttl <= 0:
                        sid = k.split(":")[-1]
                        self.cleanup_session(sid)
            except Exception:
                pass
