import unittest
import threading
import time

from aegis_attacker.llm_advisor import ESCALATION_MODELS, escalated_model
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


class TestSingleFlight(unittest.TestCase):
    def test_stop_event_wakes_waiter_without_mutating_playbook_from_signal_path(self):
        pb = Playbook()
        self.assertEqual(pb.claim_or_wait("fp"), "solve")
        results = []
        stop = threading.Event()

        waiter = threading.Thread(
            target=lambda: results.append(
                pb.claim_or_wait("fp", wait_timeout=5.0, stop_event=stop)
            )
        )
        waiter.start()
        time.sleep(0.02)
        stop.set()
        waiter.join(0.5)

        self.assertFalse(waiter.is_alive())
        self.assertEqual(results, ["skip"])

    def test_first_caller_solves_others_wait_then_reuse(self):
        pb = Playbook()
        # 첫 표적: solve 권한 획득
        self.assertEqual(pb.claim_or_wait("fp"), "solve")
        # 두 번째 표적: solver 진행 중 — 짧은 대기 후 아직 미해결이면 skip
        self.assertEqual(pb.claim_or_wait("fp", wait_timeout=0.01), "skip")
        # solver가 성공 기록 후 종료
        pb.record("fp", {"method": "GET", "path": "/admin"})
        pb.finish_llm("fp")
        # 이후 표적: playbook 재사용
        self.assertEqual(pb.claim_or_wait("fp"), "reuse")

    def test_failed_solver_lets_next_become_solver(self):
        pb = Playbook()
        self.assertEqual(pb.claim_or_wait("fp"), "solve")
        pb.finish_llm("fp")  # 성공 없이 종료(기록 없음)
        # 답이 없으므로 다음 표적이 새 solver가 된다
        self.assertEqual(pb.claim_or_wait("fp"), "solve")

    def test_empty_fingerprint_always_solves(self):
        pb = Playbook()
        self.assertEqual(pb.claim_or_wait(""), "solve")
        pb.finish_llm("")  # 안전(무동작)

    def test_concurrent_claims_single_solver(self):
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
        # 정확히 하나만 solve, 나머지는 skip(미해결) — 동시 LLM 폭주 방지
        self.assertEqual(results.count("solve"), 1)
        self.assertEqual(results.count("skip"), 5)


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
