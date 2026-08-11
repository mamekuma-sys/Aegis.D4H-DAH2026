import unittest

from aegis_attacker.models import Endpoint, ExecutionPlan, Outcome
from aegis_attacker.observation import HttpResponse
from aegis_attacker.rate_limit import RateLimiter
from aegis_attacker.tools import (
    ExecutionAdapter,
    Scope,
    ScopeViolation,
    double_encode_tokens,
    evasion_variants,
    insert_sql_comments,
    url_encode_tokens,
    vary_keyword_case,
)

IN = Endpoint("team2.lig.internal", 8082)
OUT = Endpoint("evil.example.com", 80)


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class ScriptedHttp:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        self.calls.append((method, url, headers, body, timeout))
        idx = min(len(self.calls) - 1, len(self.responses) - 1)
        return self.responses[idx]


def make_adapter(responses, scope_eps=(IN,)):
    clk = FakeClock()
    rl = RateLimiter(clock=clk, sleep=lambda dt: clk.advance(dt))
    http = ScriptedHttp(responses)
    return ExecutionAdapter(http, rl, Scope(scope_eps), clock=clk), http


class TestScope(unittest.TestCase):
    def test_in_scope(self):
        self.assertTrue(Scope([IN]).contains(IN))

    def test_out_of_scope_rejected(self):
        adapter, http = make_adapter([HttpResponse(200, "x")])
        plan = ExecutionPlan("http", OUT, {"method": "GET", "path": "/"})
        with self.assertRaises(ScopeViolation):
            adapter.execute(plan)
        self.assertEqual(len(http.calls), 0)  # 범위 밖은 요청조차 안 감


class TestExecute(unittest.TestCase):
    def test_success(self):
        adapter, http = make_adapter([HttpResponse(200, "FLAG{x}", {"X-Flag": "1"})])
        plan = ExecutionPlan("http", IN, {"method": "GET", "path": "/fetch?url=127.0.0.1"})
        result = adapter.execute(plan)
        self.assertEqual(result.outcome, Outcome.SUCCESS)
        self.assertEqual(result.body, "FLAG{x}")
        self.assertEqual(result.observation.status, 200)

    def test_no_response_is_timeout_outcome(self):
        adapter, _ = make_adapter([HttpResponse(0, "")])
        plan = ExecutionPlan("http", IN, {"method": "GET", "path": "/x"})
        result = adapter.execute(plan)
        self.assertEqual(result.outcome, Outcome.TIMEOUT)
        self.assertTrue(result.observation.no_response)

    def test_path_normalized_and_quoted(self):
        adapter, http = make_adapter([HttpResponse(200, "ok")])
        plan = ExecutionPlan("http", IN, {"method": "GET", "path": "admin"})
        adapter.execute(plan)
        _, url, _, _, _ = http.calls[0]
        self.assertEqual(url, "http://team2.lig.internal:8082/admin")


class TestEvasion(unittest.TestCase):
    def test_url_encode(self):
        self.assertEqual(url_encode_tokens("../etc"), "%2e%2e%2fetc")
        self.assertEqual(url_encode_tokens("a' OR"), "a%27+OR")

    def test_double_encode(self):
        self.assertIn("%252e%252e%252f", double_encode_tokens("../x"))

    def test_case_vary_changes_keyword(self):
        out = vary_keyword_case("1 UNION SELECT 1")
        self.assertNotIn("UNION SELECT", out)
        self.assertIn("union", out.lower())

    def test_comment_insertion(self):
        self.assertIn("UN/**/ION", insert_sql_comments("UNION SELECT"))

    def test_variants_preserve_intent_and_differ(self):
        variants = evasion_variants("1' UNION SELECT sql FROM sqlite_master")
        self.assertTrue(len(variants) >= 2)
        for v in variants:
            self.assertNotEqual(v, "1' UNION SELECT sql FROM sqlite_master")


if __name__ == "__main__":
    unittest.main()
