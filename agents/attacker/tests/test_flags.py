import unittest

from aegis_attacker.flags import (
    FlagPipeline,
    FlagStore,
    SubmitClient,
    extract_flags,
    flag_fingerprint,
    is_valid_flag,
)
from aegis_attacker.models import SubmitState
from aegis_attacker.observation import HttpResponse
from aegis_attacker.rate_limit import RateLimiter


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class ScriptedHttp:
    """호출마다 지정된 응답을 순서대로 반환. 마지막 응답을 반복."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        self.calls.append((method, url, headers, body, timeout))
        if len(self.calls) <= len(self.responses):
            return self.responses[len(self.calls) - 1]
        return self.responses[-1]


def make_client(responses):
    clk = FakeClock()
    rl = RateLimiter(clock=clk, sleep=lambda dt: clk.advance(dt))
    http = ScriptedHttp(responses)
    client = SubmitClient(http, rl, "http://backend:4100/submit", "tok-team1",
                          sleep=lambda dt: clk.advance(dt))
    return client, http


class TestExtract(unittest.TestCase):
    def test_extract_dedup_order(self):
        text = "junk FLAG{a} more FLAG{b} FLAG{a}"
        self.assertEqual(extract_flags(text), ["FLAG{a}", "FLAG{b}"])

    def test_no_flag(self):
        self.assertEqual(extract_flags("nothing here"), [])

    def test_valid_flag(self):
        self.assertTrue(is_valid_flag("FLAG{x}"))
        self.assertFalse(is_valid_flag("FLAG{x} trailing"))
        self.assertFalse(is_valid_flag("nope"))

    def test_fingerprint_hides_plaintext(self):
        fp = flag_fingerprint("FLAG{secret}")
        self.assertNotIn("secret", fp)
        self.assertEqual(fp, flag_fingerprint("FLAG{secret}"))


class TestStore(unittest.TestCase):
    def test_resolved_after_terminal_state(self):
        s = FlagStore()
        self.assertFalse(s.is_resolved("FLAG{x}"))
        s.record("FLAG{x}", SubmitState.ACCEPTED)
        self.assertTrue(s.is_resolved("FLAG{x}"))
        self.assertEqual(s.accepted_count(), 1)

    def test_error_not_resolved(self):
        s = FlagStore()
        s.record("FLAG{x}", SubmitState.ERROR)
        self.assertFalse(s.is_resolved("FLAG{x}"))  # ERROR는 재시도 가능


class TestSubmitClient(unittest.TestCase):
    def test_accepted(self):
        client, _ = make_client([HttpResponse(200, '{"status":"accepted","correct":true}')])
        self.assertEqual(client.submit("FLAG{x}"), SubmitState.ACCEPTED)

    def test_own_team_and_duplicate_and_rejected_closed(self):
        for status, expect in [
            ("own_team", SubmitState.OWN_TEAM),
            ("duplicate", SubmitState.DUPLICATE),
            ("rejected", SubmitState.REJECTED),
            ("closed", SubmitState.CLOSED),
        ]:
            client, _ = make_client([HttpResponse(200, '{"status":"%s"}' % status)])
            self.assertEqual(client.submit("FLAG{x}"), expect)

    def test_429_then_success_backoff(self):
        client, http = make_client([
            HttpResponse(429, "rate"),
            HttpResponse(200, '{"status":"accepted"}'),
        ])
        self.assertEqual(client.submit("FLAG{x}"), SubmitState.ACCEPTED)
        self.assertEqual(len(http.calls), 2)  # 429 후 재시도

    def test_network_error(self):
        client, _ = make_client([HttpResponse(0, "")])
        self.assertEqual(client.submit("FLAG{x}"), SubmitState.ERROR)


class TestPipeline(unittest.TestCase):
    def test_process_submits_once_per_flag(self):
        client, http = make_client([HttpResponse(200, '{"status":"accepted"}')])
        pipe = FlagPipeline(client)
        # 같은 flag가 응답에 2번, 이후 다른 경로 응답에도 등장 → 제출은 1회
        r1 = pipe.process("FLAG{win} FLAG{win}")
        r2 = pipe.process("later again FLAG{win}")
        self.assertEqual(len(r1), 1)
        self.assertEqual(r1[0][1], SubmitState.ACCEPTED)
        self.assertEqual(r2[0][1], SubmitState.ACCEPTED)  # 저장소에서 반환, 재제출 안 함
        self.assertEqual(len(http.calls), 1)  # 실제 제출 1회
        self.assertEqual(pipe.store.accepted_count(), 1)

    def test_no_flag_no_submit(self):
        client, http = make_client([HttpResponse(200, '{"status":"accepted"}')])
        pipe = FlagPipeline(client)
        self.assertEqual(pipe.process("no flag here"), [])
        self.assertEqual(len(http.calls), 0)


if __name__ == "__main__":
    unittest.main()
