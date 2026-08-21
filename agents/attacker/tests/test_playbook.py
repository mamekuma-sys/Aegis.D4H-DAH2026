import threading
import unittest

from aegis_attacker.playbook import Playbook


class TestPlaybook(unittest.TestCase):
    def test_record_and_lookup(self):
        pb = Playbook()
        pb.record("fp-abc", {"method": "GET", "path": "/fetch?url=x", "reason": "ssrf"})
        got = pb.lookup("fp-abc")
        self.assertEqual(got["method"], "GET")
        self.assertEqual(got["path"], "/fetch?url=x")

    def test_sanitize_keeps_exploit_shape(self):
        # 재사용에 필요한 exploit 형태(method·path·headers·body)를 보관한다.
        # 인증형 exploit은 권한 헤더가 핵심이므로 헤더를 버리면 교차 재사용이 깨진다.
        pb = Playbook()
        pb.record("fp", {"method": "post", "path": "/admin",
                         "headers": {"X-Role": "admin"}, "body": "q=1"})
        got = pb.lookup("fp")
        self.assertEqual(set(got.keys()), {"method", "path", "headers", "body"})
        self.assertEqual(got["method"], "POST")
        self.assertEqual(got["headers"], {"X-Role": "admin"})
        self.assertEqual(got["body"], "q=1")

    def test_sanitize_defaults_missing_shape(self):
        pb = Playbook()
        pb.record("fp", {"path": "/x"})
        got = pb.lookup("fp")
        self.assertEqual(got["headers"], {})
        self.assertEqual(got["body"], "")

    def test_stricter_successful_delivery_supersedes_raw_form(self):
        pb = Playbook()
        self.assertEqual(pb.generation, 0)
        pb.record("fp", {"path": "/a"})
        self.assertEqual(pb.generation, 1)
        pb.record("fp", {"path": "/b"})
        self.assertEqual(pb.lookup("fp")["path"], "/b")
        self.assertEqual(pb.generation, 2)
        pb.record("fp", {"path": "/b"})
        self.assertEqual(pb.generation, 2)

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
        self.assertEqual(pb.generation, 0)


class TestBudgetBurnClaims(unittest.TestCase):
    """$1360 한도 소진을 위해 claim_or_wait는 항상 solve를 반환한다."""

    def test_every_claim_is_solve(self):
        pb = Playbook()
        self.assertEqual(pb.claim_or_wait("fp"), "solve")
        self.assertEqual(pb.claim_or_wait("fp", wait_timeout=0.01), "solve")
        pb.record("fp", {"method": "GET", "path": "/admin"})
        pb.finish_llm("fp")
        self.assertEqual(pb.claim_or_wait("fp"), "solve")

    def test_empty_fingerprint_always_solves(self):
        pb = Playbook()
        self.assertEqual(pb.claim_or_wait(""), "solve")
        pb.finish_llm("")  # 안전(무동작)

    def test_concurrent_claims_all_solve(self):
        pb = Playbook()
        results = []
        lock = threading.Lock()

        def worker():
            d = pb.claim_or_wait("fp", wait_timeout=0.05)
            with lock:
                results.append(d)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count("solve"), 6)
        self.assertEqual(results.count("skip"), 0)


if __name__ == "__main__":
    unittest.main()
