import json
import unittest
from urllib.parse import urlsplit

from aegis_attacker.config import AttackerConfig
from aegis_attacker.models import SubmitState
from aegis_attacker.observation import HttpResponse
from aegis_attacker.runtime import AttackerRuntime


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def make_cfg():
    return AttackerConfig(
        targets=("t2.lig.internal",), ports=(8082,),
        submit_url="http://backend:4100/submit", submit_token="tok-team1",
        llm_base_url="http://litellm:4000", llm_api_key="sk-team1", llm_model="gpt-4o-mini",
    )


class FakeArena:
    """LLM·제출·표적을 하나로 흉내낸다. exploit_path와 flag_when으로 시나리오 제어."""

    def __init__(self, banner, exploit_path, flag, drop_raw=False, flag_when=None):
        self.banner = banner
        self.exploit_path = exploit_path
        self.flag = flag
        self.drop_raw = drop_raw
        self.flag_when = flag_when or (lambda full: full != "/")
        self.submits = []

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        if "/v1/chat/completions" in url:
            content = json.dumps({
                "vuln": "OTHER", "method": "GET", "path": self.exploit_path,
                "headers": {}, "body": "", "reason": "test exploit",
            })
            return HttpResponse(200, json.dumps({
                "choices": [{"message": {"content": content}}],
                "usage": {"total_tokens": 10},
            }))
        if url.endswith("/submit"):
            self.submits.append(json.loads(body))
            return HttpResponse(200, json.dumps({"status": "accepted", "correct": True}))
        # 표적 요청
        parts = urlsplit(url)
        full = parts.path + (("?" + parts.query) if parts.query else "")
        if parts.path == "/" and not parts.query:
            return HttpResponse(200, self.banner, {})
        low = full.lower()
        if self.drop_raw and "../" in full and "%2e" not in low:
            return HttpResponse(0, "")  # 시그니처 필터 DROP
        if self.flag_when(full):
            return HttpResponse(200, self.flag, {})
        return HttpResponse(200, "no flag yet", {})


def make_runtime(arena):
    clk = FakeClock()
    return AttackerRuntime(
        make_cfg(), http=arena,
        clock=clk, sleep=lambda dt: clk.advance(dt),
    )


class TestRuntimeEndToEnd(unittest.TestCase):
    def test_captures_and_submits_flag(self):
        arena = FakeArena("URL Fetcher — GET /fetch?url=<url>", "/fetch?url=x", "FLAG{ssrf_win}")
        rt = make_runtime(arena)
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(len(arena.submits), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{ssrf_win}")
        self.assertEqual(arena.submits[0]["token"], "tok-team1")

    def test_flag_in_banner_captured(self):
        arena = FakeArena("welcome FLAG{banner_flag} here", "/x", "irrelevant")
        rt = make_runtime(arena)
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{banner_flag}")

    def test_signature_evasion_recovers_dropped_request(self):
        # 원본 ../ 요청은 필터에 DROP, URL 인코딩 회피 변형이 통과해 flag 획득
        arena = FakeArena(
            "File reader — GET /read?f=<path>", "/read?f=../flag", "FLAG{evaded}",
            drop_raw=True, flag_when=lambda full: "%2e" in full.lower(),
        )
        rt = make_runtime(arena)
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{evaded}")

    def test_no_flag_no_submit(self):
        arena = FakeArena("boring service", "/x", "FLAG{x}", flag_when=lambda full: False)
        rt = make_runtime(arena)
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 0)
        self.assertEqual(len(arena.submits), 0)
        self.assertGreater(report.requests_made, 1)  # 관측·시도는 했음

    def test_error_isolated_per_target(self):
        class BoomTransport:
            def request(self, *a, **k):
                raise RuntimeError("network boom")
        rt = make_runtime(FakeArena("b", "/x", "FLAG{x}"))
        rt.transport = BoomTransport()  # egress는 run_once에서 이 transport로 구성됨
        # 예외가 run_once 전체를 죽이지 않고 표적 단위로 격리된다
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 0)


class TestRuntimeInert(unittest.TestCase):
    def test_inert_without_llm_key_returns(self):
        cfg = AttackerConfig(targets=("t2",), ports=(8082,), llm_api_key="")
        logs = []
        from aegis_attacker.audit import AuditLogger
        rt = AttackerRuntime(cfg, http=FakeArena("b", "/x", "f"),
                             audit=AuditLogger(sink=logs.append))
        rt.run_forever()  # can_attack False → 즉시 반환(무한 루프 아님)
        self.assertTrue(any("inert" in line for line in logs))


if __name__ == "__main__":
    unittest.main()
