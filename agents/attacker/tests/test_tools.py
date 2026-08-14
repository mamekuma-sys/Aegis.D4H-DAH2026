import unittest

from aegis_attacker.config import AttackerConfig
from aegis_attacker.egress import EgressGateway, build_allowlists
from aegis_attacker.models import (
    Capability,
    Endpoint,
    EvidenceRef,
    ExecutionPlan,
    Outcome,
    SideEffectClass,
)
from aegis_attacker.observation import HttpResponse
from aegis_attacker.rate_limit import RateLimiter
from aegis_attacker.recon import discover_paths
from aegis_attacker.tools import (
    ExecutionAdapter,
    PlanBindingError,
    double_encode_tokens,
    evasion_arg_variants,
    evasion_variants,
    insert_sql_comments,
    url_encode_tokens,
    vary_keyword_case,
)

IN = Endpoint("team2.lig.internal", 8082)
CFG = AttackerConfig(targets=("team2.lig.internal",), ports=(8082,), llm_api_key="k")
ROUND = "r1"


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        self.calls.append((method, url))
        idx = min(len(self.calls) - 1, len(self.responses) - 1)
        return self.responses[idx]


def make_adapter(responses):
    clk = FakeClock()
    rl = RateLimiter(clock=clk, sleep=lambda dt: clk.advance(dt))
    gw = EgressGateway(FakeTransport(responses), build_allowlists(CFG))
    return ExecutionAdapter(gw, rl, round_id=ROUND, clock=clk), gw


def fresh_evidence(endpoint=IN):
    return EvidenceRef("e1", ROUND, endpoint.endpoint_id, 0.0, 1000.0, "fp")


def make_plan(path="/fetch?url=x", endpoint=IN, evidence=None, **over):
    kw = dict(
        tool="http", target=endpoint,
        args={"method": "GET", "path": path},
        round_id=ROUND, endpoint_id=endpoint.endpoint_id,
        capability=Capability.ATTACK_TARGET,
        evidence_refs=[evidence or fresh_evidence(endpoint)],
        created_at_monotonic=0.0, expires_at_monotonic=1000.0,
        side_effect_class=SideEffectClass.READ_ONLY,
    )
    kw.update(over)
    return ExecutionPlan(**kw)


class TestExecute(unittest.TestCase):
    def test_success(self):
        adapter, _ = make_adapter([HttpResponse(200, "FLAG{x}", {"X-Flag": "1"})])
        result = adapter.execute(make_plan())
        self.assertEqual(result.outcome, Outcome.SUCCESS)
        self.assertEqual(result.body, "FLAG{x}")
        self.assertEqual(result.observation.round_id, ROUND)
        self.assertIsNotNone(result.observation.evidence_ref)

    def test_no_response_is_timeout(self):
        adapter, _ = make_adapter([HttpResponse(0, "")])
        result = adapter.execute(make_plan(path="/x"))
        self.assertEqual(result.outcome, Outcome.TIMEOUT)
        self.assertTrue(result.observation.no_response)

    def test_path_quoted(self):
        adapter, gw = make_adapter([HttpResponse(200, "ok")])
        adapter.execute(make_plan(path="admin"))
        _, url = gw._transport.calls[0]
        self.assertEqual(url, "http://team2.lig.internal:8082/admin")


class TestBindingValidation(unittest.TestCase):
    def test_out_of_scope_rejected_by_egress(self):
        from aegis_attacker.egress import EgressError
        adapter, _ = make_adapter([HttpResponse(200, "x")])
        out = Endpoint("evil.com", 80)
        plan = make_plan(endpoint=out)
        with self.assertRaises(EgressError):
            adapter.execute(plan)

    def test_no_evidence_rejected(self):
        adapter, gw = make_adapter([HttpResponse(200, "x")])
        plan = make_plan()
        plan.evidence_refs = []
        with self.assertRaises(PlanBindingError):
            adapter.execute(plan)
        self.assertEqual(len(gw._transport.calls), 0)  # 네트워크 호출 전에 거부

    def test_expired_evidence_rejected(self):
        adapter, _ = make_adapter([HttpResponse(200, "x")])
        stale = EvidenceRef("e", ROUND, IN.endpoint_id, 0.0, 0.0, "fp")  # 즉시 만료
        with self.assertRaises(PlanBindingError):
            adapter.execute(make_plan(evidence=stale, expires_at_monotonic=0.0))

    def test_round_mismatch_rejected(self):
        adapter, _ = make_adapter([HttpResponse(200, "x")])
        with self.assertRaises(PlanBindingError):
            adapter.execute(make_plan(round_id="other-round"))

    def test_wrong_capability_rejected(self):
        adapter, _ = make_adapter([HttpResponse(200, "x")])
        with self.assertRaises(PlanBindingError):
            adapter.execute(make_plan(capability=Capability.SUBMIT))

    def test_disallowed_side_effect_rejected(self):
        adapter, _ = make_adapter([HttpResponse(200, "x")])
        with self.assertRaises(PlanBindingError):
            adapter.execute(make_plan(side_effect_class=SideEffectClass.DISALLOWED))

    def test_mutation_without_preconditions_rejected(self):
        adapter, _ = make_adapter([HttpResponse(200, "x")])
        with self.assertRaises(PlanBindingError):
            adapter.execute(make_plan(
                side_effect_class=SideEffectClass.BOUNDED_FLAG_DIRECTED_MUTATION,
                preconditions=[]))

    def test_mutation_with_preconditions_allowed(self):
        adapter, _ = make_adapter([HttpResponse(200, "ok")])
        result = adapter.execute(make_plan(
            side_effect_class=SideEffectClass.BOUNDED_FLAG_DIRECTED_MUTATION,
            preconditions=["bounded", "safe-stop"]))
        self.assertEqual(result.outcome, Outcome.SUCCESS)


class TestEvasion(unittest.TestCase):
    def test_url_encode(self):
        self.assertEqual(url_encode_tokens("../etc"), "%2e%2e%2fetc")

    def test_double_encode(self):
        self.assertIn("%252e%252e%252f", double_encode_tokens("../x"))

    def test_case_vary(self):
        out = vary_keyword_case("1 UNION SELECT 1")
        self.assertNotIn("UNION SELECT", out)

    def test_comment_insertion(self):
        self.assertIn("UN/**/ION", insert_sql_comments("UNION SELECT"))

    def test_variants_differ(self):
        variants = evasion_variants("1' UNION SELECT sql FROM sqlite_master")
        self.assertTrue(len(variants) >= 2)

    def test_arg_variants_encode_path_and_body(self):
        # path 뿐 아니라 body 의 의심 토큰도 인코딩한다(필터는 본문 시그니처로도 DROP).
        variants = evasion_arg_variants({
            "method": "POST", "path": "/read?f=../x",
            "headers": {}, "body": "q=1' OR '1'='1"})
        self.assertTrue(len(variants) >= 1)
        first = variants[0]
        self.assertNotEqual(first["path"], "/read?f=../x")  # path 인코딩됨
        # 최소 한 변형은 body 도 인코딩한다
        self.assertTrue(any(v["body"] != "q=1' OR '1'='1" for v in variants))

    def test_arg_variants_empty_when_no_tokens(self):
        # 인코딩할 의심 토큰이 없으면 변형을 만들지 않는다.
        variants = evasion_arg_variants({"method": "GET", "path": "/x", "headers": {}, "body": ""})
        self.assertEqual(variants, [])


class TestReconDiscovery(unittest.TestCase):
    def test_discover_from_robots(self):
        paths = discover_paths("User-agent: *\nDisallow: /admin\nAllow: /public\nSitemap: /sitemap.xml")
        self.assertIn("/admin", paths)
        self.assertIn("/public", paths)

    def test_discover_from_banner_paths(self):
        paths = discover_paths("URL Fetcher — GET /fetch?url=<url> also see /registry")
        self.assertIn("/fetch", paths)   # 쿼리 앞까지
        self.assertIn("/registry", paths)

    def test_static_assets_skipped(self):
        paths = discover_paths("<link href=/style.css> <script src=/app.js> <a href=/portal>")
        self.assertNotIn("/style.css", paths)
        self.assertNotIn("/app.js", paths)
        self.assertIn("/portal", paths)

    def test_bounded(self):
        text = " ".join("/p%d" % i for i in range(50))
        self.assertLessEqual(len(discover_paths(text)), 8)


if __name__ == "__main__":
    unittest.main()
