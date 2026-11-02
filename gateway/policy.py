"""
policy.py
Thành viên 2: Quản lý Chính sách và Cấp quyền (Dynamic Policy Engine)
"""

from typing import Dict, Any


class PolicyEngine:
    def __init__(self, allow_network_default: bool = False, max_timeout_sec: int = 60):
        self.allow_network_default = allow_network_default
        self.max_timeout_sec = max_timeout_sec

    def evaluate(self, inspection_result: Dict[str, Any], requested_network: bool = False) -> Dict[str, Any]:
        """
        Đánh giá quyết định thực thi:
        - ALLOW: Cho phép chạy ngay
        - REQUIRE_CONFIRMATION: Cần xác nhận từ con người (HITL)
        - REJECT: Từ chối thực thi
        """
        risk_level = inspection_result.get("risk_level", "LOW")
        violations = inspection_result.get("violations", [])

        if risk_level == "CRITICAL":
            return {
                "decision": "REJECT",
                "reason": f"Phát hiện rủi ro mức độ CRITICAL: {', '.join(violations)}",
                "can_proceed": False,
            }

        if risk_level == "HIGH" or (requested_network and not self.allow_network_default):
            return {
                "decision": "REQUIRE_CONFIRMATION",
                "reason": "Yêu cầu quyền mạng hoặc phát hiện mẫu câu lệnh rủi ro cao.",
                "can_proceed": False,
            }

        return {
            "decision": "ALLOW",
            "reason": "Vượt qua kiểm tra an toàn chính sách.",
            "can_proceed": True,
        }
