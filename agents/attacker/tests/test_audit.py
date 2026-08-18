import json
import unittest

from aegis_attacker.audit import AuditLogger, Redactor


class TestRedactor(unittest.TestCase):
    def test_scrub_flag(self):
        r = Redactor()
        self.assertEqual(r.scrub("got FLAG{abc123} here"), "got [FLAG] here")

    def test_scrub_long_final_format_flag(self):
        r = Redactor()
        secret = "FLAG{" + ("a" * 512) + "}"
        self.assertNotIn("a" * 32, r.scrub("got " + secret))

    def test_scrub_secrets(self):
        r = Redactor(secrets={"tok-team1", "sk-supersecret"})
        out = r.scrub("token=tok-team1 key=sk-supersecret")
        self.assertNotIn("tok-team1", out)
        self.assertNotIn("sk-supersecret", out)
        self.assertIn("[REDACTED]", out)

    def test_short_secret_ignored(self):
        # 너무 짧은 비밀은 오탐 치환 방지
        r = Redactor(secrets={"ab"})
        self.assertEqual(r.scrub("abcd"), "abcd")

    def test_scrub_nested_obj(self):
        r = Redactor(secrets={"tok-team1"})
        obj = {"a": "FLAG{x}", "b": ["tok-team1", 3], "c": {"d": "FLAG{y}"}}
        out = r.scrub_obj(obj)
        self.assertEqual(out["a"], "[FLAG]")
        self.assertEqual(out["b"][0], "[REDACTED]")
        self.assertEqual(out["b"][1], 3)
        self.assertEqual(out["c"]["d"], "[FLAG]")


class TestAuditLogger(unittest.TestCase):
    def test_log_line_has_no_secrets(self):
        lines = []
        logger = AuditLogger(Redactor(secrets={"tok-team1"}), sink=lines.append)
        logger.log("attack", flag="FLAG{win}", token="tok-team1", status=200)
        rec = json.loads(lines[0])
        self.assertEqual(rec["event"], "attack")
        self.assertEqual(rec["flag"], "[FLAG]")
        self.assertEqual(rec["token"], "[REDACTED]")
        self.assertEqual(rec["status"], 200)
        self.assertNotIn("FLAG{win}", lines[0])
        self.assertNotIn("tok-team1", lines[0])


if __name__ == "__main__":
    unittest.main()
