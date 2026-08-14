import unittest

from aegis_attacker.llm_advisor import ESCALATION_MODELS, escalated_model
from aegis_attacker.playbook import Playbook


class TestPlaybook(unittest.TestCase):
    def test_record_and_lookup(self):
        pb = Playbook()
        pb.record("fp-abc", {"method": "GET", "path": "/fetch?url=x", "reason": "ssrf"})
        got = pb.lookup("fp-abc")
        self.assertEqual(got["method"], "GET")
        self.assertEqual(got["path"], "/fetch?url=x")

    def test_sanitize_keeps_shape_redacts_secrets(self):
        # method·path·headers·body 형태는 보존하되 Cookie/Authorization/flag 원문은 마스크한다.
        pb = Playbook()
        pb.record("fp", {
            "method": "post", "path": "/login",
            "headers": {"Cookie": "sess=secret", "Authorization": "Bearer abc",
                        "X-Role": "admin"},
            "body": "user=admin&flag=FLAG{leak}"})
        got = pb.lookup("fp")
        self.assertEqual(set(got.keys()), {"method", "path", "headers", "body"})
        self.assertEqual(got["method"], "POST")
        # 자격증명 값은 마스크(세션은 표적별이라 교차 재사용 금지)
        self.assertNotIn("secret", str(got["headers"]))
        self.assertNotIn("Bearer abc", str(got["headers"]))
        # 기법 힌트 헤더(X-Role: admin)는 형태로 보존
        self.assertEqual(got["headers"]["X-Role"], "admin")
        # body 의 flag 원문은 제거, 형태는 유지
        self.assertNotIn("FLAG{leak}", got["body"])
        self.assertIn("user=admin", got["body"])

    def test_first_write_wins(self):
        pb = Playbook()
        pb.record("fp", {"path": "/a"})
        pb.record("fp", {"path": "/b"})
        self.assertEqual(pb.lookup("fp")["path"], "/a")

    def test_missing_and_empty(self):
        pb = Playbook()
        self.assertIsNone(pb.lookup("nope"))
        pb.record("", {"path": "/x"})  # 빈 fingerprint 무시
        self.assertIsNone(pb.lookup(""))

    def test_clear(self):
        pb = Playbook()
        pb.record("fp", {"path": "/x"})
        pb.clear()
        self.assertIsNone(pb.lookup("fp"))


class TestModelEscalation(unittest.TestCase):
    def test_level_0_uses_base(self):
        self.assertEqual(escalated_model("gpt-4o-mini", 0), "gpt-4o-mini")

    def test_escalates(self):
        self.assertEqual(escalated_model("gpt-4o-mini", 1), ESCALATION_MODELS[0])
        self.assertEqual(escalated_model("gpt-4o-mini", 2), ESCALATION_MODELS[1])

    def test_caps_at_top(self):
        self.assertEqual(escalated_model("gpt-4o-mini", 99), ESCALATION_MODELS[-1])


if __name__ == "__main__":
    unittest.main()
