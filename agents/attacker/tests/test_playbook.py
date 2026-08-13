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

    def test_sanitize_drops_non_shape(self):
        # 비밀·부가 필드는 재사용 형태에 남기지 않는다(method·path만)
        pb = Playbook()
        pb.record("fp", {"method": "post", "path": "/x", "headers": {"Cookie": "sess=secret"}})
        got = pb.lookup("fp")
        self.assertEqual(set(got.keys()), {"method", "path"})
        self.assertEqual(got["method"], "POST")

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
