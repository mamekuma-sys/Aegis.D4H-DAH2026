import json
import unittest
from urllib.parse import urlsplit

from aegis_attacker.config import AttackerConfig
from aegis_attacker.models import Capability, SubmitState
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
        # flag는 LLM exploit 경로(/fetch?url=)에서만 — 배너가 노출한 /fetch 만으로는 안 나오게
        # 해서 recon(경로 탐지)이 아니라 LLM 경로가 실제로 동작함을 검증한다.
        arena = FakeArena("URL Fetcher — GET /fetch?url=<url>", "/fetch?url=x", "FLAG{ssrf_win}",
                          flag_when=lambda full: "url=" in full and full.startswith("/fetch"))
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
    def test_llm_down_does_not_stop_observation_or_submit(self):
        # LLM 장애(500)여도 관측·범위검사·제출 결정론 경로는 계속. 배너 flag는 잡힌다.
        arena = FakeArena("welcome FLAG{banner} here", "/x", "irrelevant", llm_status=500)
        rt = make_runtime(arena)
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)  # 배너 flag 제출됨
        self.assertGreater(report.requests_made, 0)

    def test_secrets_persist_across_passes_until_shutdown(self):
        # 설계: Round = 컨테이너 수명. run_once 마다 비밀을 지우지 않는다(4초 폐기 금지).
        arena = FakeArena("URL Fetcher", "/fetch?url=x", "FLAG{win}")
        rt = make_runtime(arena)
        rt.run_once()
        # 제출 토큰·LLM 키 원문은 다음 pass 재사용을 위해 컨테이너 수명 동안 유지된다.
        self.assertNotEqual(rt._secret_store.secrets_snapshot(), set())
        # 컨테이너 종료(shutdown) 시에만 원문을 폐기한다.
        rt.shutdown()
        self.assertEqual(rt._secret_store.secrets_snapshot(), set())

    def test_budget_resets_on_new_runtime(self):
        # 컨테이너 수명 = 1 Round. _build_round 시작 시 예산을 0으로 되돌린다.
        arena = FakeArena("URL Fetcher — GET /fetch?url=<url>", "/fetch?url=x", "FLAG{win}",
                          flag_when=lambda full: full.startswith("/fetch"))
        rt = make_runtime(arena)
        rt.budget.llm_calls = 9
        rt.run_once()
        self.assertLess(rt.budget.llm_calls, 9)  # _build_round 가 reset 함

    def test_playbook_and_dedup_persist_across_passes(self):
        # 설계: playbook·flag 중복 집합을 4초 루프마다 버리지 않는다.
        arena = FakeArena("URL Fetcher — GET /fetch?url=<url>", "/fetch?url=x", "FLAG{win}",
                          flag_when=lambda full: "url=" in full and full.startswith("/fetch"))
        rt = make_runtime(arena)
        rt.run_once()
        first_llm = arena.llm_calls
        self.assertEqual(rt._report.accepted_count(), 1)
        # 두 번째 pass: 이미 딴 표적은 재공격하지 않는다 → 추가 LLM 호출·제출 없음
        rt.run_once()
        self.assertEqual(arena.llm_calls, first_llm)
        self.assertEqual(len(arena.submits), 1)  # 재제출 없음(중복 집합 유지)


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
        # exploit 은 쿼리(url=)까지 있어야 flag — 배너가 노출한 경로만으론 recon 이 못 딴다.
        if "url=" in full and full.startswith(self.exploit_prefix):
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
    def test_inert_without_targets_rechecks(self):
        # 표적/포트가 없을 때만 inert. LLM 키가 아니라 표적 부재가 inert 조건이다(§9.13).
        cfg = AttackerConfig(targets=(), ports=(), llm_api_key="sk-x")
        logs = []
        from aegis_attacker.audit import AuditLogger
        rt = AttackerRuntime(cfg, http=FakeArena("b", "/x", "f"),
                             audit=AuditLogger(sink=logs.append))
        rt.run_forever(max_passes=2)  # 주기적 재점검 — 무한 루프 아님
        self.assertTrue(any('"inert"' in line for line in logs))

    def test_no_llm_key_still_recon_and_submits(self):
        # LLM 키가 없어도 표적이 있으면 run_forever 가 배너/recon/제출을 수행한다.
        # flag 는 recon 경로(/flag)에 있으므로 LLM 없이 제출까지 도달해야 한다.
        arena = FakeArena("plain service", "/unused", "FLAG{no_llm_win}",
                          flag_when=lambda full: full.startswith("/flag"))
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8082,),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="", concurrency=1)
        clk = FakeClock()
        rt = AttackerRuntime(cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt))
        rt.run_forever(max_passes=1)
        self.assertEqual(len(arena.submits), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{no_llm_win}")
        self.assertEqual(arena.llm_calls, 0)  # LLM 조언 호출 없음


class TestPlaybookShapeReuse(unittest.TestCase):
    def test_auth_post_shape_reused_without_second_llm(self):
        # 한 컨테이너 안에서 AUTH/POST exploit 형태(headers/body)가 두 번째 LLM 없이 재사용된다.
        import threading as _t

        class AuthArena:
            def __init__(self):
                self.banner = "Admin Portal — POST /login"
                self.llm_calls = 0
                self.submits = []
                self._lock = _t.Lock()

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                if "/v1/chat/completions" in url:
                    with self._lock:
                        self.llm_calls += 1
                    content = json.dumps({
                        "vuln": "AUTH", "method": "POST", "path": "/login",
                        "headers": {"X-Role": "admin"}, "body": "user=admin&pass=x",
                        "reason": "priv-esc"})
                    return HttpResponse(200, json.dumps({
                        "choices": [{"message": {"content": content}}],
                        "usage": {"total_tokens": 10}}))
                if url.endswith("/submit"):
                    with self._lock:
                        self.submits.append(json.loads(body))
                    return HttpResponse(200, json.dumps({"status": "accepted"}))
                parts = urlsplit(url)
                if parts.path == "/" and not parts.query:
                    return HttpResponse(200, self.banner)
                # POST /login 에 X-Role:admin 헤더 + body 가 있을 때만 flag(형태 재사용 검증)
                if (method == "POST" and parts.path == "/login"
                        and (headers or {}).get("X-Role") == "admin" and body):
                    return HttpResponse(200, "FLAG{port_%s}" % parts.port)
                return HttpResponse(200, "no flag yet")

        arena = AuthArena()
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8082, 8083),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_base_url="http://litellm:4000", llm_api_key="sk-team1",
            llm_model="gpt-4o-mini", concurrency=1)
        clk = FakeClock()
        rt = AttackerRuntime(cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt))
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 2)   # 두 포트 다 flag
        self.assertEqual(arena.llm_calls, 1)           # 두 번째는 playbook headers/body 재사용


class ThreadSafeClock:
    def __init__(self):
        self._t = 0.0
        self._lock = __import__("threading").Lock()

    def __call__(self):
        with self._lock:
            return self._t

    def advance(self, dt):
        with self._lock:
            self._t += dt


class ConcurrentFlagArena:
    """모든 표적이 같은 FLAG 를 응답한다. 동시 제출이 한 번만 일어나는지 검증용."""

    def __init__(self, flag="FLAG{shared}"):
        import threading as _t
        self.flag = flag
        self.submits = []
        self.target_hits = 0
        self._lock = _t.Lock()

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        if url.endswith("/submit"):
            with self._lock:
                self.submits.append(json.loads(body))
            return HttpResponse(200, json.dumps({"status": "accepted"}))
        # 모든 표적 요청이 즉시 같은 flag 를 배너로 반환
        with self._lock:
            self.target_hits += 1
        return HttpResponse(200, "welcome %s" % self.flag)


class TestConcurrentSubmitDedup(unittest.TestCase):
    def test_twenty_threads_same_flag_one_submit(self):
        from aegis_attacker.flags import FlagPipeline, FlagStore, SubmitClient
        from aegis_attacker.egress import EgressGateway
        from aegis_attacker.rate_limit import RateLimiter
        from aegis_attacker.secrets import KIND_SUBMIT_TOKEN, RoundSecretStore
        import threading as _t

        SUBMIT_URL = "http://backend:4100/submit"
        ALLOW = {Capability.SUBMIT: {("backend", 4100)}}

        class CountingTransport:
            def __init__(self):
                self.calls = 0
                self._lock = _t.Lock()

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                with self._lock:
                    self.calls += 1
                return HttpResponse(200, json.dumps({"status": "accepted"}))

        clk = ThreadSafeClock()
        rl = RateLimiter(clock=clk, sleep=lambda dt: clk.advance(dt))
        transport = CountingTransport()
        gw = EgressGateway(transport, ALLOW)
        store = RoundSecretStore("r1", clock=clk)
        token = store.put(KIND_SUBMIT_TOKEN, "tok-team1")
        client = SubmitClient(gw, rl, SUBMIT_URL, token, store,
                              clock=clk, sleep=lambda dt: clk.advance(dt))
        pipe = FlagPipeline(client, store, FlagStore())

        barrier = _t.Barrier(20)
        results = []
        rlock = _t.Lock()

        def worker():
            barrier.wait()  # 20 스레드가 동시에 같은 flag 를 제출 시도
            out = pipe.process("here is FLAG{shared} take it")
            with rlock:
                results.append(out)

        threads = [_t.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(transport.calls, 1)  # 정확히 한 번만 HTTP 제출
        # 모든 워커가 동일한 ACCEPTED 결과를 공유받는다
        self.assertTrue(all(r[0][1] == SubmitState.ACCEPTED for r in results))


class TestParallelAttack(unittest.TestCase):
    def test_parallel_captures_all_targets(self):
        # concurrency>1: 여러 포트를 동시에 공격, 공유 상태(락)로 안전하게 집계
        arena = MultiPortArena("URL Fetcher — GET /fetch?url=<url>", "/fetch")
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8082, 8083, 8084, 8085),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_base_url="http://litellm:4000", llm_api_key="sk-team1",
            llm_model="gpt-4o-mini", concurrency=4)
        # 관대한 rate limiter(테스트 속도) — 병렬 정확성·공유 상태 락 검증
        from aegis_attacker.rate_limit import RateLimiter
        rt = AttackerRuntime(cfg, http=arena,
                             rate=RateLimiter(request_burst=10000, submit_max=10000))
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 4)  # 네 포트 flag 모두 수집
        flags = {s["flag"] for s in arena.submits}
        self.assertEqual(len(flags), 4)  # 포트별 서로 다른 flag

    def test_parallel_with_default_rate_limiter_respects_burst_and_submit(self):
        # 설계 요구: request_burst=10000 우회가 아니라 DEFAULT RateLimiter(버스트 20)로 병렬 검증.
        from aegis_attacker.rate_limit import RateLimiter, REQUEST_BURST, SUBMIT_MAX
        import threading as _t

        clk = ThreadSafeClock()

        class TimedArena:
            """모든 표적 요청 시각을 기록해 초기 버스트가 20 이하인지 검증한다."""

            def __init__(self):
                self.banner = "URL Fetcher — GET /fetch?url=<url>"
                self.req_times = []
                self.submits = []
                self.llm_calls = 0
                self._lock = _t.Lock()

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                if "/v1/chat/completions" in url:
                    with self._lock:
                        self.llm_calls += 1
                    content = json.dumps({"vuln": "OTHER", "method": "GET",
                                          "path": "/fetch?url=x", "headers": {},
                                          "body": "", "reason": "x"})
                    return HttpResponse(200, json.dumps({
                        "choices": [{"message": {"content": content}}],
                        "usage": {"total_tokens": 10}}))
                if url.endswith("/submit"):
                    with self._lock:
                        self.submits.append(json.loads(body))
                    return HttpResponse(200, json.dumps({"status": "accepted"}))
                with self._lock:
                    self.req_times.append(clk())  # 토큰버킷 통과 시각(공유 clock)
                parts = urlsplit(url)
                full = parts.path + (("?" + parts.query) if parts.query else "")
                if parts.path == "/" and not parts.query:
                    return HttpResponse(200, self.banner)
                if "url=" in full and full.startswith("/fetch"):
                    return HttpResponse(200, "FLAG{port_%s}" % parts.port)
                return HttpResponse(200, "no flag yet")

        arena = TimedArena()
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8082, 8083, 8084, 8085),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_base_url="http://litellm:4000", llm_api_key="sk-team1",
            llm_model="gpt-4o-mini", concurrency=4)
        rate = RateLimiter(clock=clk, sleep=lambda dt: clk.advance(dt))  # DEFAULT 버스트 20
        rt = AttackerRuntime(cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt),
                             rate=rate)
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 4)  # 정확성 유지
        # 초기 버스트: clock 이 advance 되기 전(t==0) 통과한 요청은 버스트 상한 이하여야 한다.
        initial_burst = sum(1 for t in arena.req_times if t == 0.0)
        self.assertLessEqual(initial_burst, REQUEST_BURST)
        # 리필 전 총 요청 수가 버스트를 넘었다면 limiter 가 실제로 개입(sleep→advance)했다는 뜻.
        self.assertGreater(len(arena.req_times), REQUEST_BURST)
        self.assertGreater(clk(), 0.0)  # 토큰버킷이 대기를 유발함
        self.assertLessEqual(len(arena.submits), SUBMIT_MAX)  # 60초당 30 이하


if __name__ == "__main__":
    unittest.main()
