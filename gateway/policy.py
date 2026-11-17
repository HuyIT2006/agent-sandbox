"""
policy.py
Thành viên 2: Quản lý Chính sách Động và Quy trình Human-in-the-Loop (Dynamic Policy Engine & HITL)
Hỗ trợ Dynamic Rules (Allowlist, Denylist), Risk Matrix và quản lý Confirmation Token an toàn.
"""

import os
import secrets
import threading
import time
from typing import Dict, Any, List, Optional, Set, Tuple


class PendingApproval:
    """Mô hình dữ liệu lưu trữ yêu cầu đang chờ phê duyệt từ con người (HITL)."""

    def __init__(
        self,
        token: str,
        tool_type: str,
        code: str,
        session_id: Optional[str] = None,
        allow_network: bool = False,
        timeout: int = 20,
        ttl_seconds: int = 300,
    ):
        self.token = token
        self.tool_type = tool_type
        self.code = code  # Lưu nguyên bản payload ban đầu, không thay đổi
        self.session_id = session_id
        self.allow_network = allow_network
        self.timeout = timeout
        self.created_at = time.time()
        self.expires_at = self.created_at + ttl_seconds
        self.status = "PENDING"  # PENDING | APPROVED | REJECTED | EXPIRED | CONSUMED

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "tool_type": self.tool_type,
            "session_id": self.session_id,
            "allow_network": self.allow_network,
            "timeout": self.timeout,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "expires_in": max(0, int(self.expires_at - time.time())),
        }


class PolicyEngine:
    """
    Dynamic Policy Engine:
    - Đánh giá mức độ rủi ro (LOW, MEDIUM, HIGH, CRITICAL).
    - Hỗ trợ Denylist và Allowlist động (Denylist luôn có độ ưu tiên cao hơn).
    - Quản lý vòng đời Confirmation Token cho quy trình Human-in-the-Loop (HITL).
    """

    def __init__(
        self,
        allow_network_default: bool = False,
        max_timeout_sec: int = 60,
        token_ttl_seconds: int = 300,
        allowlist: Optional[Set[str]] = None,
        denylist: Optional[Set[str]] = None,
    ):
        self.allow_network_default = allow_network_default
        self.max_timeout_sec = max_timeout_sec
        self.token_ttl_seconds = token_ttl_seconds
        self.allowlist: Set[str] = set(allowlist or [])
        self.denylist: Set[str] = set(denylist or [])

        # Bộ lưu trữ in-memory cho các Pending Approvals (có Thread Lock bảo vệ chống race condition)
        self._pending_approvals: Dict[str, PendingApproval] = {}
        self._lock = threading.Lock()

    # =========================================================================
    # 1. ĐÁNH GIÁ CHÍNH SÁCH (POLICY EVALUATION)
    # =========================================================================
    def evaluate(
        self,
        inspection_result: Dict[str, Any],
        requested_network: bool = False,
        command_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Đánh giá quyết định thực thi:
        - ALLOW: Cho phép chạy ngay
        - REQUIRE_CONFIRMATION: Cần xác nhận từ con người (HITL)
        - REJECT: Từ chối thực thi

        Quy tắc:
        1. Denylist luôn có mức ưu tiên cao nhất -> REJECT.
        2. Rủi ro CRITICAL luôn bị REJECT (không được allowlist hay HITL override).
        3. Rủi ro HIGH hoặc yêu cầu quyền mạng -> REQUIRE_CONFIRMATION.
        4. Allowlist có thể cho phép các lệnh LOW/MEDIUM mà không cần kiểm tra thêm.
        5. Rủi ro MEDIUM -> Cho phép chạy nhưng có cảnh báo hoặc REQUIRE_CONFIRMATION nếu vi phạm chính sách.
        6. Rủi ro LOW -> ALLOW.
        """
        risk_level = inspection_result.get("risk_level", "LOW")
        violations = inspection_result.get("violations", [])
        code_or_cmd = command_override or inspection_result.get("command") or inspection_result.get("code") or ""
        code_or_cmd_stripped = code_or_cmd.strip()

        # 1. Kiểm tra Denylist động (Ưu tiên cao nhất)
        for denied_pattern in self.denylist:
            if denied_pattern and (denied_pattern == code_or_cmd_stripped or denied_pattern in code_or_cmd):
                return {
                    "decision": "REJECT",
                    "risk_level": "CRITICAL",
                    "reason": f"Lệnh nằm trong Denylist bị cấm tuyệt đối: '{denied_pattern}'",
                    "violations": violations + [f"Khớp mẫu Denylist: {denied_pattern}"],
                    "can_proceed": False,
                    "require_confirmation": False,
                }

        # 2. Xử lý mức độ CRITICAL (Tuyệt đối không cho phép override)
        if risk_level == "CRITICAL":
            return {
                "decision": "REJECT",
                "risk_level": "CRITICAL",
                "reason": f"Phát hiện rủi ro mức độ CRITICAL: {', '.join(violations)}",
                "violations": violations,
                "can_proceed": False,
                "require_confirmation": False,
            }

        # 3. Kiểm tra Allowlist động (Chỉ áp dụng khi KHÔNG phải CRITICAL)
        if code_or_cmd_stripped in self.allowlist:
            # Nếu trong allowlist nhưng yêu cầu network mà network mặc định tắt -> vẫn cần HITL
            if requested_network and not self.allow_network_default:
                return {
                    "decision": "REQUIRE_CONFIRMATION",
                    "risk_level": "MEDIUM",
                    "reason": "Lệnh nằm trong Allowlist nhưng yêu cầu kích hoạt kết nối mạng ngoài.",
                    "violations": violations,
                    "can_proceed": False,
                    "require_confirmation": True,
                }
            return {
                "decision": "ALLOW",
                "risk_level": "LOW",
                "reason": "Lệnh nằm trong Allowlist được phê duyệt trước.",
                "violations": violations,
                "can_proceed": True,
                "require_confirmation": False,
            }

        # 4. Yêu cầu quyền mạng (Network Egress) khi chưa được bật mặc định
        if requested_network and not self.allow_network_default:
            return {
                "decision": "REQUIRE_CONFIRMATION",
                "risk_level": "HIGH" if risk_level == "LOW" else risk_level,
                "reason": "Yêu cầu quyền truy cập mạng ngoài (cần con người phê duyệt).",
                "violations": violations + ["Yêu cầu kích hoạt kết nối mạng ngoài"],
                "can_proceed": False,
                "require_confirmation": True,
            }

        # 5. Rủi ro mức độ HIGH
        if risk_level == "HIGH":
            return {
                "decision": "REQUIRE_CONFIRMATION",
                "risk_level": "HIGH",
                "reason": f"Phát hiện mẫu lệnh rủi ro cao (HIGH): {', '.join(violations)}",
                "violations": violations,
                "can_proceed": False,
                "require_confirmation": True,
            }

        # 6. Rủi ro mức độ MEDIUM (ví dụ mở file cục bộ)
        if risk_level == "MEDIUM":
            return {
                "decision": "ALLOW",
                "risk_level": "MEDIUM",
                "reason": "Thao tác có rủi ro trung bình, được phép thực thi trong giới hạn Sandbox.",
                "violations": violations,
                "can_proceed": True,
                "require_confirmation": False,
            }

        # 7. Rủi ro LOW
        return {
            "decision": "ALLOW",
            "risk_level": "LOW",
            "reason": "Vượt qua kiểm tra an toàn chính sách.",
            "violations": violations,
            "can_proceed": True,
            "require_confirmation": False,
        }

    # =========================================================================
    # 2. QUẢN LÝ HUMAN-IN-THE-LOOP (HITL) TOKENS
    # =========================================================================
    def create_pending_approval(
        self,
        tool_type: str,
        code: str,
        session_id: Optional[str] = None,
        allow_network: bool = False,
        timeout: int = 20,
    ) -> PendingApproval:
        """Sinh confirmation token ngẫu nhiên entropy cao bằng secrets và lưu pending request."""
        # Sinh token 256-bit an toàn
        token = secrets.token_urlsafe(32)

        approval = PendingApproval(
            token=token,
            tool_type=tool_type,
            code=code,
            session_id=session_id,
            allow_network=allow_network,
            timeout=timeout,
            ttl_seconds=self.token_ttl_seconds,
        )

        with self._lock:
            # Dọn dẹp sơ bộ các token hết hạn
            self._cleanup_expired_tokens_locked()
            self._pending_approvals[token] = approval

        return approval

    def get_pending_approval(self, token: str) -> Optional[PendingApproval]:
        """Lấy thông tin pending approval theo token (kiểm tra hạn dùng)."""
        with self._lock:
            approval = self._pending_approvals.get(token)
            if not approval:
                return None
            if approval.is_expired():
                approval.status = "EXPIRED"
            return approval

    def resolve_pending_approval(
        self,
        token: str,
        decision: str,
    ) -> Tuple[bool, str, Optional[PendingApproval]]:
        """
        Xác nhận token một cách atomic (nguyên tử):
        - Chỉ cho phép chuyển trạng thái khi token đang PENDING và chưa hết hạn.
        - Trả về: (thành công, thông báo lỗi nếu có, đối tượng PendingApproval)
        """
        normalized_decision = decision.strip().upper()
        if normalized_decision not in ("APPROVED", "REJECTED"):
            return False, "Quyết định không hợp lệ (chỉ chấp nhận 'APPROVED' hoặc 'REJECTED')", None

        with self._lock:
            approval = self._pending_approvals.get(token)
            if not approval:
                return False, "Confirmation token không tồn tại", None

            if approval.is_expired():
                approval.status = "EXPIRED"
                return False, "Confirmation token đã hết hạn", None

            if approval.status == "CONSUMED":
                return False, "Confirmation token đã được sử dụng trước đó (chống tái sử dụng)", None

            if approval.status == "REJECTED":
                return False, "Confirmation token đã bị từ chối trước đó", None

            if approval.status != "PENDING":
                return False, f"Trạng thái token không hợp lệ: {approval.status}", None

            # Cập nhật trạng thái atomic
            if normalized_decision == "APPROVED":
                approval.status = "CONSUMED"  # Đánh dấu đã tiêu thụ để không bị chạy lại lần 2
            else:
                approval.status = "REJECTED"

            return True, "", approval

    def _cleanup_expired_tokens_locked(self):
        """Dọn dẹp token hết hạn trong bộ nhớ (gọi bên trong context lock)."""
        now = time.time()
        expired_tokens = [
            t for t, apprv in self._pending_approvals.items()
            if now > apprv.expires_at or apprv.status in ("CONSUMED", "REJECTED")
        ]
        # Giữ lại token vừa xử lý trong 1 khoảng thời gian ngắn để chống replay, xóa những token quá hạn
        for t in expired_tokens:
            if now > self._pending_approvals[t].expires_at + 60:
                del self._pending_approvals[t]
