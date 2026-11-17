"""
test_policy_session.py
Bộ Unit Test toàn diện cho Giai đoạn 2 - Nhiệm vụ 2 (Thành viên 2)
Kiểm thử Dynamic Policy Engine, Human-in-the-Loop (HITL) Workflow,
Confirmation Token Lifecycle, và SessionManager với In-memory Fallback & Workspace Protection.
"""

import os
import shutil
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Thêm thư mục gốc dự án vào sys.path
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gateway.policy import PolicyEngine, PendingApproval
from gateway.session_manager import SessionManager, BASE_WORKSPACE_DIR
from gateway.api import ExecuteRequest, ConfirmRequest, execute_tool, confirm_execution
from fastapi import HTTPException


# =====================================================================
# NHÓM 1: DYNAMIC POLICY ENGINE TESTS
# =====================================================================
class TestDynamicPolicyEngine(unittest.TestCase):
    """Kiểm thử Dynamic Policy Engine, Matrix rủi ro, Allowlist và Denylist."""

    def setUp(self):
        self.policy = PolicyEngine(
            allow_network_default=False,
            allowlist={"echo 'allowed'", "uname -a"},
            denylist={"curl http://forbidden.com", "bash -i"},
        )

    def test_01_allow_standard_safe_action(self):
        """Hành động an toàn mức LOW được ALLOW."""
        res = self.policy.evaluate({"risk_level": "LOW", "violations": []})
        self.assertEqual(res["decision"], "ALLOW")
        self.assertTrue(res["can_proceed"])
        self.assertFalse(res["require_confirmation"])

    def test_02_require_confirmation_high_risk(self):
        """Hành động mức HIGH yêu cầu xác nhận REQUIRE_CONFIRMATION."""
        res = self.policy.evaluate({"risk_level": "HIGH", "violations": ["Cú pháp có dấu hiệu rủi ro"]})
        self.assertEqual(res["decision"], "REQUIRE_CONFIRMATION")
        self.assertFalse(res["can_proceed"])
        self.assertTrue(res["require_confirmation"])

    def test_03_require_confirmation_network_request(self):
        """Yêu cầu quyền mạng khi chưa bật mặc định phải REQUIRE_CONFIRMATION."""
        res = self.policy.evaluate(
            {"risk_level": "LOW", "violations": []},
            requested_network=True,
        )
        self.assertEqual(res["decision"], "REQUIRE_CONFIRMATION")
        self.assertFalse(res["can_proceed"])
        self.assertTrue(res["require_confirmation"])

    def test_04_reject_critical_risk(self):
        """Hành vi mức CRITICAL luôn bị REJECT bắt buộc."""
        res = self.policy.evaluate({"risk_level": "CRITICAL", "violations": ["Fork Bomb", "rm -rf /"]})
        self.assertEqual(res["decision"], "REJECT")
        self.assertFalse(res["can_proceed"])
        self.assertFalse(res["require_confirmation"])

    def test_05_dynamic_allowlist(self):
        """Lệnh nằm trong Allowlist được ALLOW mà không cần xác nhận."""
        res = self.policy.evaluate(
            {"risk_level": "MEDIUM", "violations": ["Lệnh thông thường"], "command": "uname -a"}
        )
        self.assertEqual(res["decision"], "ALLOW")
        self.assertTrue(res["can_proceed"])

    def test_06_dynamic_denylist(self):
        """Lệnh nằm trong Denylist bị REJECT ngay lập tức."""
        res = self.policy.evaluate(
            {"risk_level": "LOW", "violations": [], "command": "curl http://forbidden.com"}
        )
        self.assertEqual(res["decision"], "REJECT")
        self.assertFalse(res["can_proceed"])

    def test_07_denylist_takes_precedence_over_allowlist(self):
        """Denylist luôn có độ ưu tiên cao hơn Allowlist nếu có xung đột."""
        conflicting_policy = PolicyEngine(
            allowlist={"sample_cmd"},
            denylist={"sample_cmd"},
        )
        res = conflicting_policy.evaluate(
            {"risk_level": "LOW", "violations": [], "command": "sample_cmd"}
        )
        self.assertEqual(res["decision"], "REJECT")
        self.assertIn("Denylist", res["reason"])

    def test_08_allowlist_cannot_override_critical(self):
        """Allowlist TUYỆT ĐỐI không thể ghi đè mức rủi ro CRITICAL."""
        tricky_policy = PolicyEngine(allowlist={"rm -rf /"})
        res = tricky_policy.evaluate(
            {"risk_level": "CRITICAL", "violations": ["Xóa thư mục gốc"], "command": "rm -rf /"}
        )
        self.assertEqual(res["decision"], "REJECT")


# =====================================================================
# NHÓM 2: CONFIRMATION TOKEN & PENDING APPROVAL LIFECYCLE
# =====================================================================
class TestConfirmationTokenLifecycle(unittest.TestCase):
    """Kiểm thử vòng đời Confirmation Token, tính ngẫu nhiên, hạn dùng và chống replay."""

    def setUp(self):
        self.policy = PolicyEngine(token_ttl_seconds=2)  # TTL 2 giây để test expiry nhanh

    def test_01_token_generation_entropy(self):
        """Sinh token ngẫu nhiên entropy cao và lưu đúng payload ban đầu."""
        approval = self.policy.create_pending_approval(
            tool_type="bash",
            code="echo 'payload'",
            session_id="test_sess_01",
            allow_network=True,
            timeout=15,
        )
        self.assertIsNotNone(approval.token)
        self.assertTrue(len(approval.token) >= 32)
        self.assertEqual(approval.status, "PENDING")
        self.assertEqual(approval.code, "echo 'payload'")

    def test_02_token_expiration(self):
        """Token hết hạn không thể được phê duyệt."""
        approval = self.policy.create_pending_approval(tool_type="bash", code="ls")
        time.sleep(2.1)

        success, err_msg, apprv = self.policy.resolve_pending_approval(
            token=approval.token,
            decision="APPROVED",
        )
        self.assertFalse(success)
        self.assertIn("hết hạn", err_msg)

    def test_03_nonexistent_token(self):
        """Xác nhận token không tồn tại trả về lỗi rõ ràng."""
        success, err_msg, apprv = self.policy.resolve_pending_approval(
            token="invalid_random_token_123",
            decision="APPROVED",
        )
        self.assertFalse(success)
        self.assertIn("không tồn tại", err_msg)

    def test_04_token_reuse_prevention(self):
        """Token đã phê duyệt chuyển sang CONSUMED và không thể sử dụng lại."""
        approval = self.policy.create_pending_approval(tool_type="python", code="print(1)")

        # Lần 1: Thành công
        ok1, err1, apprv1 = self.policy.resolve_pending_approval(approval.token, "APPROVED")
        self.assertTrue(ok1)
        self.assertEqual(apprv1.status, "CONSUMED")

        # Lần 2: Thất bại do chống replay
        ok2, err2, apprv2 = self.policy.resolve_pending_approval(approval.token, "APPROVED")
        self.assertFalse(ok2)
        self.assertIn("đã được sử dụng", err2)

    def test_05_token_rejected_cannot_be_approved_later(self):
        """Token đã bị REJECTED không thể được phê duyệt sau đó."""
        approval = self.policy.create_pending_approval(tool_type="bash", code="ls")

        # Từ chối token
        ok_rej, _, _ = self.policy.resolve_pending_approval(approval.token, "REJECTED")
        self.assertTrue(ok_rej)

        # Cố gắng phê duyệt lại
        ok_app, err, _ = self.policy.resolve_pending_approval(approval.token, "APPROVED")
        self.assertFalse(ok_app)
        self.assertIn("từ chối", err)


# =====================================================================
# NHÓM 3: HITL API ENDPOINTS INTEGRATION
# =====================================================================
class TestHITLAPIEndpoints(unittest.TestCase):
    """Kiểm thử trực tiếp logic các endpoint execute_tool và confirm_execution."""

    @patch("gateway.api.runner.execute")
    def test_01_execute_allow_flow(self, mock_runner_exec):
        """Yêu cầu an toàn được thực thi ngay (ALLOW)."""
        mock_runner_exec.return_value = {
            "stdout": "Hello",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 10,
            "sandbox_id": "sbx_allow",
        }
        req = ExecuteRequest(tool_type="bash", code="echo Hello")
        res = execute_tool(req)
        self.assertTrue(res.success)
        self.assertEqual(res.status, "EXECUTED")
        mock_runner_exec.assert_called_once()

    @patch("gateway.api.runner.execute")
    def test_02_execute_require_confirmation_flow(self, mock_runner_exec):
        """Yêu cầu mạng (allow_network=True) tạo confirmation_token và KHÔNG gọi runner."""
        req = ExecuteRequest(tool_type="bash", code="ping 8.8.8.8", allow_network=True)
        res = execute_tool(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status, "REQUIRE_CONFIRMATION")
        self.assertIsNotNone(res.confirmation_token)
        self.assertTrue(res.expires_in > 0)
        mock_runner_exec.assert_not_called()

    @patch("gateway.api.runner.execute")
    def test_03_execute_reject_flow(self, mock_runner_exec):
        """Yêu cầu chứa mã độc CRITICAL bị từ chối REJECT và không sinh token."""
        req = ExecuteRequest(tool_type="bash", code="rm -rf /")
        res = execute_tool(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status, "REJECT")
        self.assertIsNone(res.confirmation_token)
        mock_runner_exec.assert_not_called()

    @patch("gateway.api.runner.execute")
    def test_04_confirm_approved_flow(self, mock_runner_exec):
        """Phê duyệt token (APPROVED) thực thi đúng payload gốc bằng SandboxRunner."""
        mock_runner_exec.return_value = {
            "stdout": "Network ping ok",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 25,
            "sandbox_id": "sbx_hitl_ok",
        }
        # 1. Gửi request cần HITL
        req_exec = ExecuteRequest(tool_type="bash", code="curl http://api.internal", allow_network=True)
        exec_res = execute_tool(req_exec)
        token = exec_res.confirmation_token

        # 2. Gửi request phê duyệt
        req_confirm = ConfirmRequest(confirmation_token=token, decision="APPROVED")
        confirm_res = confirm_execution(req_confirm)
        self.assertTrue(confirm_res.success)
        self.assertEqual(confirm_res.status, "EXECUTED")
        mock_runner_exec.assert_called_once()

    @patch("gateway.api.runner.execute")
    def test_05_confirm_rejected_flow(self, mock_runner_exec):
        """Từ chối token (REJECTED) không gọi SandboxRunner."""
        req_exec = ExecuteRequest(tool_type="bash", code="ls", allow_network=True)
        exec_res = execute_tool(req_exec)
        token = exec_res.confirmation_token

        req_confirm = ConfirmRequest(confirmation_token=token, decision="REJECTED")
        confirm_res = confirm_execution(req_confirm)
        self.assertEqual(confirm_res.status, "REJECTED")
        mock_runner_exec.assert_not_called()

    def test_06_confirm_errors_invalid_or_expired(self):
        """Kiểm tra ngoại lệ HTTPException khi confirm token không hợp lệ (404)."""
        req_bad = ConfirmRequest(confirmation_token="non_existent_token_xyz", decision="APPROVED")
        with self.assertRaises(HTTPException) as ctx:
            confirm_execution(req_bad)
        self.assertEqual(ctx.exception.status_code, 404)


# =====================================================================
# NHÓM 4: SESSION MANAGER & WORKSPACE PROTECTION
# =====================================================================
class TestSessionManager(unittest.TestCase):
    """Kiểm thử Session Manager, In-memory Fallback, TTL và bảo vệ Workspace."""

    def setUp(self):
        self.test_dir = Path("./tmp_test_workspaces").resolve()
        self.sm = SessionManager(
            ttl_seconds=3,
            redis_url="redis://invalid-host:9999/0",  # Ép buộc kích hoạt fallback
            base_dir=self.test_dir,
        )

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_in_memory_fallback_active(self):
        """Khi Redis không kết nối được, hệ thống tự động chạy In-memory Fallback an toàn."""
        self.assertEqual(self.sm.backend_type, "IN_MEMORY")
        self.assertFalse(self.sm.is_redis_active)

    def test_02_create_and_get_session(self):
        """Tạo và truy xuất thông tin session."""
        ws = self.sm.get_or_create_workspace("sess_100")
        self.assertTrue(Path(ws).exists())

        sess_meta = self.sm.get_session("sess_100")
        self.assertIsNotNone(sess_meta)
        self.assertEqual(sess_meta["session_id"], "sess_100")
        self.assertEqual(sess_meta["status"], "ACTIVE")

    def test_03_touch_session_renewal(self):
        """Gia hạn session thành công."""
        self.sm.get_or_create_workspace("sess_touch")
        t1 = self.sm.get_session("sess_touch")["last_active"]
        time.sleep(0.1)
        self.sm.touch_session("sess_touch")
        t2 = self.sm.get_session("sess_touch")["last_active"]
        self.assertGreater(t2, t1)

    def test_04_cleanup_session_removes_workspace(self):
        """Xóa session sẽ dọn dẹp sạch thư mục workspace trên đĩa."""
        ws = self.sm.get_or_create_workspace("sess_cleanup")
        test_file = Path(ws) / "data.txt"
        test_file.write_text("temporary data")
        self.assertTrue(test_file.exists())

        self.sm.cleanup_session("sess_cleanup")
        self.assertFalse(Path(ws).exists())
        self.assertIsNone(self.sm.get_session("sess_cleanup"))

    def test_05_cleanup_expired_sessions(self):
        """Dọn dẹp tự động các session đã quá TTL."""
        ws = self.sm.get_or_create_workspace("sess_expired")
        time.sleep(3.2)  # Quá TTL 3s
        self.sm.cleanup_expired()
        self.assertFalse(Path(ws).exists())

    def test_06_path_traversal_prevention(self):
        """Ngăn chặn mọi nỗ lực dùng session_id chứa ký tự Path Traversal."""
        malicious_ids = [
            "../../etc",
            "../other_folder",
            "sess/sub",
            "sess\\sub",
            "sess; rm -rf /",
            "   ",
        ]
        for mid in malicious_ids:
            with self.subTest(session_id=mid):
                with self.assertRaises(ValueError):
                    self.sm.get_or_create_workspace(mid)


if __name__ == "__main__":
    print("==============================================================")
    print("   RUNNING GATEWAY PHASE 2 UNIT & INTEGRATION TEST SUITE      ")
    print("==============================================================")
    unittest.main()
