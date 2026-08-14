import unittest

from aegis_attacker.egress import EgressGateway
from aegis_attacker.flags import (
    FlagPipeline,
    FlagStore,
    SubmitClient,
    extract_flags,
    flag_fingerprint,
    is_valid_flag,
)
from aegis_attacker.models import Capability, SubmitState
from aegis_attacker.observation import HttpResponse
from aegis_attacker.rate_limit import RateLimiter
from aegis_attacker.secrets import KIND_FLAG, KIND_SUBMIT_TOKEN, RoundSecretStore

SUBMIT_URL = "http://backend:4100/submit"
ALLOW = {Capability.SUBMIT: {("backend", 4100)}}


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class ScriptedTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        self.calls.append(body)
        idx = min(len(self.calls) - 1, len(self.responses) - 1)
        return self.responses[idx]


def make_client(responses, round_deadline=float("inf")):
    clk = FakeClock()
    rl = RateLimiter(clock=clk, sleep=lambda dt: clk.advance(dt))
    transport = ScriptedTransport(responses)
    gw = EgressGateway(transport, ALLOW)
    store = RoundSecretStore("r1", clock=clk)
    token_handle = store.put(KIND_SUBMIT_TOKEN, "tok-team1")
    client = SubmitClient(gw, rl, SUBMIT_URL, token_handle, store,
                          clock=clk, sleep=lambda dt: clk.advance(dt),
                          round_deadline=round_deadline)
    return client, store, transport


class TestExtract(unittest.TestCase):
    def test_extract_dedup(self):
        self.assertEqual(extract_flags("FLAG{a} FLAG{b} FLAG{a}"), ["FLAG{a}", "FLAG{b}"])

    def test_valid(self):
        self.assertTrue(is_valid_flag("FLAG{x}"))
        self.assertFalse(is_valid_flag("FLAG{x} extra"))

    def test_fingerprint_hides(self):
        self.assertNotIn("secret", flag_fingerprint("FLAG{secret}"))


class TestStore(unittest.TestCase):
    def test_resolved_after_terminal(self):
        s = FlagStore()
        h = flag_fingerprint("FLAG{x}")
        self.assertFalse(s.is_resolved(h))
        s.record(h, SubmitState.ACCEPTED)
        self.assertTrue(s.is_resolved(h))

    def test_error_not_resolved(self):
        s = FlagStore()
        h = flag_fingerprint("FLAG{x}")
        s.record(h, SubmitState.ERROR)
        self.assertFalse(s.is_resolved(h))


class TestSubmitClient(unittest.TestCase):
    def test_accepted_via_handle(self):
        client, store, transport = make_client([HttpResponse(200, '{"status":"accepted"}')])
        fh = store.put(KIND_FLAG, "FLAG{x}")
        self.assertEqual(client.submit(fh), SubmitState.ACCEPTED)
        # 제출 본문에 원문 flag·token이 실려 전송됨(제출 클라이언트만 원문 소비)
        self.assertIn("FLAG{x}", transport.calls[0])
        self.assertIn("tok-team1", transport.calls[0])

    def test_states(self):
        for status, expect in [("own_team", SubmitState.OWN_TEAM),
                               ("duplicate", SubmitState.DUPLICATE),
                               ("rejected", SubmitState.REJECTED),
                               ("closed", SubmitState.CLOSED)]:
            client, store, _ = make_client([HttpResponse(200, '{"status":"%s"}' % status)])
            fh = store.put(KIND_FLAG, "FLAG{x}")
            self.assertEqual(client.submit(fh), expect)

    def test_429_retry_after_honored(self):
        client, store, transport = make_client([
            HttpResponse(429, "rate", {"Retry-After": "2"}),
            HttpResponse(200, '{"status":"accepted"}'),
        ])
        fh = store.put(KIND_FLAG, "FLAG{x}")
        self.assertEqual(client.submit(fh), SubmitState.ACCEPTED)
        self.assertEqual(len(transport.calls), 2)

    def test_429_beyond_round_deadline_no_retry(self):
        client, store, transport = make_client(
            [HttpResponse(429, "rate", {"Retry-After": "50"})], round_deadline=1.0)
        fh = store.put(KIND_FLAG, "FLAG{x}")
        self.assertEqual(client.submit(fh), SubmitState.ERROR)  # 현 Round 재시도 안 함
        self.assertEqual(len(transport.calls), 1)

    def test_429_no_header_uses_backoff(self):
        client, store, transport = make_client([
            HttpResponse(429, "rate", {}),  # Retry-After 없음
            HttpResponse(200, '{"status":"accepted"}'),
        ])
        fh = store.put(KIND_FLAG, "FLAG{x}")
        self.assertEqual(client.submit(fh), SubmitState.ACCEPTED)


class TestPipeline(unittest.TestCase):
    def test_submits_once_per_flag(self):
        client, store, transport = make_client([HttpResponse(200, '{"status":"accepted"}')])
        pipe = FlagPipeline(client, store)
        r1 = pipe.process("FLAG{win} FLAG{win}")
        r2 = pipe.process("later FLAG{win}")
        self.assertEqual(r1[0][1], SubmitState.ACCEPTED)
        self.assertEqual(r2[0][1], SubmitState.ACCEPTED)  # 저장소에서, 재제출 안 함
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(pipe.store.accepted_count(), 1)

    def test_no_flag_no_submit(self):
        client, store, transport = make_client([HttpResponse(200, '{"status":"accepted"}')])
        pipe = FlagPipeline(client, store)
        self.assertEqual(pipe.process("nothing"), [])
        self.assertEqual(len(transport.calls), 0)

    def test_error_allows_later_retry(self):
        client, store, transport = make_client([
            HttpResponse(0, ""),
            HttpResponse(200, '{"status":"accepted"}'),
        ])
        pipe = FlagPipeline(client, store)

        self.assertEqual(pipe.process("FLAG{retry}")[0][1], SubmitState.ERROR)
        self.assertEqual(pipe.process("FLAG{retry}")[0][1], SubmitState.ACCEPTED)
        self.assertEqual(len(transport.calls), 2)


if __name__ == "__main__":
    unittest.main()
