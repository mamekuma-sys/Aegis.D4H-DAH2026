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


def make_cfg(ports=(8082,), concurrency=1):
    return AttackerConfig(
        targets=("t2.lig.internal",), ports=ports,
        submit_url="http://backend:4100/submit", submit_token="tok-team1",
        llm_base_url="http://litellm:4000", llm_api_key="sk-team1", llm_model="gpt-4o-mini",
        concurrency=concurrency,
    )


class FakeArena:
    """LLM·제출·표적을 하나로 흉내낸다. exploit_path와 flag_when으로 시나리오 제어."""

    def __init__(self, banner, exploit_path, flag, drop_raw=False, flag_when=None,
                 llm_status=200):
        self.banner = banner
        self.exploit_path = exploit_path
        self.flag = flag
        self.drop_raw = drop_raw
        self.flag_when = flag_when or (lambda full: full != "/")
        self.llm_status = llm_status
        self.submits = []
        self.llm_calls = 0

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        if "/v1/chat/completions" in url:
            self.llm_calls += 1
            if self.llm_status != 200:
                return HttpResponse(self.llm_status, "llm down")
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
        # flag는 LLM exploit 경로(/fetch)에서만 — recon 경로로는 안 나오게 해 LLM 경로를 검증
        arena = FakeArena("URL Fetcher — GET /fetch?url=<url>", "/fetch?url=x", "FLAG{ssrf_win}",
                          flag_when=lambda full: full.startswith("/fetch"))
        rt = make_runtime(arena)
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(len(arena.submits), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{ssrf_win}")
        self.assertEqual(arena.submits[0]["token"], "tok-team1")
        self.assertGreater(arena.llm_calls, 0)  # LLM exploit 경로를 실제로 탐

    def test_recon_captures_without_llm(self):
        # 흔한 경로 /flag 에서 flag → recon이 LLM 토큰 없이 획득
        arena = FakeArena("plain service", "/unused", "FLAG{recon_win}",
                          flag_when=lambda full: full.startswith("/flag"))
        rt = make_runtime(arena)
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{recon_win}")
        self.assertEqual(arena.llm_calls, 0)  # 토큰 0

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


class TestRuntimeResilience(unittest.TestCase):
    def test_run_forever_reuses_flag_store_across_scan_cycles(self):
        arena = FakeArena("FLAG{same_round}", "/x", "irrelevant")
        rt = make_runtime(arena)
        rt.run_forever(max_cycles=2)
        self.assertEqual(len(arena.submits), 1)

    def test_separate_run_once_calls_are_separate_rounds(self):
        arena = FakeArena("FLAG{new_round}", "/x", "irrelevant")
        rt = make_runtime(arena)
        rt.run_once()
        rt.run_once()
        self.assertEqual(len(arena.submits), 2)

    def test_run_once_rejects_an_active_caller_owned_round(self):
        arena = FakeArena("FLAG{caller_round}", "/x", "irrelevant")
        rt = make_runtime(arena)
        rt.start_round()
        rt.run_cycle()
        self.assertEqual(len(arena.submits), 1)

        with self.assertRaisesRegex(RuntimeError, "active Round"):
            rt.run_once()

        rt.run_cycle()
        self.assertEqual(len(arena.submits), 1)
        self.assertNotEqual(rt._secret_store.secrets_snapshot(), set())
        rt.finish_round()
        self.assertEqual(rt._secret_store.secrets_snapshot(), set())

    def test_llm_down_does_not_stop_observation_or_submit(self):
        # LLM 장애(500)여도 관측·범위검사·제출 결정론 경로는 계속. 배너 flag는 잡힌다.
        arena = FakeArena("welcome FLAG{banner} here", "/x", "irrelevant", llm_status=500)
        rt = make_runtime(arena)
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)  # 배너 flag 제출됨
        self.assertGreater(report.requests_made, 0)

    def test_round_end_wipes_secrets(self):
        arena = FakeArena("URL Fetcher", "/fetch?url=x", "FLAG{win}")
        rt = make_runtime(arena)
        rt.run_once()
        # Round 종료 시 비밀 원문 폐기
        self.assertEqual(rt._secret_store.secrets_snapshot(), set())

    def test_budget_resets_between_rounds(self):
        # LLM exploit 경로를 실제로 타서 라운드마다 llm_calls가 증가하게 한다
        arena = FakeArena("URL Fetcher — GET /fetch?url=<url>", "/fetch?url=x", "FLAG{win}",
                          flag_when=lambda full: full.startswith("/fetch"))
        rt = make_runtime(arena)
        rt.run_once()
        after_first = rt.budget.llm_calls
        self.assertGreater(after_first, 0)  # 첫 라운드에서 LLM 예산을 소비
        rt.run_once()
        # 라운드별 예산은 격리되어야 한다: 누적(2N)이 아니라 라운드 단위(N)로 리셋
        self.assertEqual(rt.budget.llm_calls, after_first)
        self.assertEqual(rt._report.summary()["llm_calls"], after_first)


class MultiPortArena:
    """여러 포트가 같은 배너를 내고 exploit 경로에서 포트별 flag를 반환한다."""

    def __init__(self, banner, exploit_prefix):
        import threading
        self.banner = banner
        self.exploit_prefix = exploit_prefix
        self.llm_calls = 0
        self.submits = []
        self._lock = threading.Lock()  # 병렬 테스트용 스레드 안전

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        if "/v1/chat/completions" in url:
            with self._lock:
                self.llm_calls += 1
            content = json.dumps({"vuln": "OTHER", "method": "GET",
                                  "path": self.exploit_prefix + "?url=x",
                                  "headers": {}, "body": "", "reason": "x"})
            return HttpResponse(200, json.dumps({
                "choices": [{"message": {"content": content}}],
                "usage": {"total_tokens": 10}}))
        if url.endswith("/submit"):
            with self._lock:
                self.submits.append(json.loads(body))
            return HttpResponse(200, json.dumps({"status": "accepted"}))
        parts = urlsplit(url)
        full = parts.path + (("?" + parts.query) if parts.query else "")
        if parts.path == "/" and not parts.query:
            return HttpResponse(200, self.banner)
        if full.startswith(self.exploit_prefix):
            return HttpResponse(200, "FLAG{port_%s}" % parts.port)
        return HttpResponse(200, "no flag yet")


class TestPlaybookReuse(unittest.TestCase):
    def test_second_target_solved_via_playbook_without_llm(self):
        arena = MultiPortArena("URL Fetcher — GET /fetch?url=<url>", "/fetch")
        clk = FakeClock()
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8082, 8083),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_base_url="http://litellm:4000", llm_api_key="sk-team1", llm_model="gpt-4o-mini")
        rt = AttackerRuntime(cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt))
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 2)          # 두 포트 다 flag
        self.assertEqual(arena.llm_calls, 1)                   # 두 번째는 playbook 재사용(LLM 0)


class TestParallelAttack(unittest.TestCase):
    def test_parallel_captures_all_targets(self):
        # concurrency>1: 여러 포트를 동시에 공격, 공유 상태(락)로 안전하게 집계
        arena = MultiPortArena("URL Fetcher — GET /fetch?url=<url>", "/fetch")
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8082, 8083, 8084, 8085),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_base_url="http://litellm:4000", llm_api_key="sk-team1",
            llm_model="gpt-4o-mini", concurrency=4)
        # 실제 스레드 + 관대한 rate limiter(테스트 속도) — 병렬 정확성·공유 상태 락 검증
        from aegis_attacker.rate_limit import RateLimiter
        rt = AttackerRuntime(cfg, http=arena,
                             rate=RateLimiter(request_burst=10000, submit_max=10000))
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 4)  # 네 포트 flag 모두 수집
        flags = {s["flag"] for s in arena.submits}
        self.assertEqual(len(flags), 4)  # 포트별 서로 다른 flag


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
