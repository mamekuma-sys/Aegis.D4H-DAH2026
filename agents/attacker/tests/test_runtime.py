import base64
import io
import json
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from aegis_attacker.audit import AuditLogger
from aegis_attacker.config import AttackerConfig, DEFAULT_LLM_MODEL
from aegis_attacker.models import SubmitState
from aegis_attacker.observation import HttpResponse
from aegis_attacker.runtime import BOOTSTRAP_RETRY_COOLDOWN, AttackerRuntime


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
        self.llm_models = []
        self.target_requests = []

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        if "/v1/chat/completions" in url:
            self.llm_calls += 1
            if body:
                try:
                    self.llm_models.append(json.loads(body).get("model"))
                except Exception:
                    pass
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
        self.target_requests.append(full)
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
    def test_l2_fresh_session_drives_rsc_and_websocket_without_logging_token(self):
        session_token = "0123456789abcdef0123456789abcdef"

        class SessionArena:
            def __init__(self):
                self.submits = []
                self.rsc_tokens = []
                self.ws_tokens = []

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                if url.endswith("/submit"):
                    self.submits.append(json.loads(body))
                    return HttpResponse(200, json.dumps({"status": "accepted"}))
                path = urlsplit(url).path
                if path == "/":
                    return HttpResponse(200, "mission console")
                if method == "POST" and path == "/api/session":
                    return HttpResponse(200, json.dumps({"sessionToken": session_token}))
                if method == "POST" and path == "/api/rsc-action":
                    document = json.loads(body)
                    self.rsc_tokens.append(document["token"])
                    expected_ref = base64.b64encode(
                        b"process.env.MC2_INTERNAL_API_TOKEN"
                    ).decode("ascii")
                    if document["ref"] == expected_ref:
                        return HttpResponse(200, "FLAG{rsc-fresh-session}")
                return HttpResponse(404, "not found")

            def request_websocket(self, host, port, path, token, timeout=6.0):
                self.ws_tokens.append(token)
                return HttpResponse(101, "FLAG{ws-fresh-session}")

        arena = SessionArena()
        stream = io.StringIO()
        cfg = make_cfg()
        clk = FakeClock()
        report = AttackerRuntime(
            cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt),
            audit=AuditLogger(sink=lambda line: stream.write(line + "\n")),
        ).run_once()

        self.assertEqual(report.accepted_count(), 2)
        self.assertEqual(arena.rsc_tokens, [session_token])
        self.assertEqual(arena.ws_tokens, [session_token])
        self.assertNotIn(session_token, stream.getvalue())

    def test_missing_submit_config_does_not_increment_submit_report(self):
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8082,),
            submit_url="", submit_token="",
            llm_base_url="http://litellm:4000", llm_api_key="sk-team1",
            llm_model="gpt-4o-mini",
        )
        arena = FakeArena("FLAG{offline}", "/unused", "irrelevant")
        clk = FakeClock()
        rt = AttackerRuntime(cfg, http=arena, clock=clk,
                             sleep=lambda dt: clk.advance(dt))

        report = rt.run_once()

        self.assertEqual(report.summary()["submit_states"], {})
        self.assertEqual(arena.submits, [])

    def test_captures_and_submits_flag(self):
        # flag는 LLM이 만든 정확한 경로(?url=x)에서만 — 결정론 엔진이 못 잡는 케이스로 LLM 경로 격리
        arena = FakeArena("URL Fetcher — GET /fetch?url=<url>", "/fetch?url=x", "FLAG{ssrf_win}",
                          flag_when=lambda full: full.endswith("?url=x"))
        rt = make_runtime(arena)
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(len(arena.submits), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{ssrf_win}")
        self.assertEqual(arena.submits[0]["token"], "tok-team1")
        self.assertGreater(arena.llm_calls, 0)  # LLM exploit 경로를 실제로 탐

    def test_probe_list_includes_fetch(self):
        from aegis_attacker.recon import COMMON_PROBE_PATHS
        self.assertIn("/fetch", COMMON_PROBE_PATHS)

    def test_finals_9000_uses_grpc_without_http_or_llm(self):
        class FinalsGrpcArena:
            def __init__(self):
                self.grpc_calls = []
                self.target_http_calls = []
                self.llm_calls = 0
                self.submits = []

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                if url.endswith("/submit"):
                    self.submits.append(json.loads(body))
                    return HttpResponse(200, json.dumps({"status": "accepted"}))
                if "/v1/chat/completions" in url:
                    self.llm_calls += 1
                    return HttpResponse(500, "unused")
                self.target_http_calls.append((method, url))
                return HttpResponse(0, "")

            def request_grpc(self, host, port, rpc, string_fields=None,
                             varint_fields=None, timeout=6.0, delivery="standard"):
                fields = dict(string_fields or {})
                self.grpc_calls.append((
                    host, port, rpc, fields, dict(varint_fields or {}), delivery
                ))
                if rpc.endswith("/Health"):
                    return HttpResponse(200, "ok")
                if rpc.endswith("/ExportDiagnosticBundle") and "${FLAG}" in fields.get(1, ""):
                    return HttpResponse(200, "AegisD4HFLAG{finals_export_first}AegisD4H")
                if rpc.endswith("/TailDiagnosticLog") and fields.get(1) == "/flag":
                    return HttpResponse(200, "FLAG{finals_grpc_fixture}")
                return HttpResponse(200, "no flag")

        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(9000,),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="", concurrency=1,
        )
        arena = FinalsGrpcArena()
        clk = FakeClock()
        report = AttackerRuntime(
            cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt)
        ).run_once()

        self.assertGreaterEqual(report.accepted_count(), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{finals_grpc_fixture}")
        self.assertEqual(arena.target_http_calls, [])
        self.assertEqual(arena.llm_calls, 0)
        self.assertTrue(arena.grpc_calls[0][2].endswith("/Health"))
        self.assertEqual(arena.grpc_calls[1][2].rsplit("/", 1)[-1], "TailDiagnosticLog")
        self.assertEqual(arena.grpc_calls[1][3].get(1), "/flag")
        self.assertEqual(arena.grpc_calls[1][5], "fragmented_huffman")

    def test_finals_9000_export_flag_echo_captures_when_tail_misses(self):
        class ExportArena:
            def __init__(self):
                self.submits = []

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                if url.endswith("/submit"):
                    self.submits.append(json.loads(body))
                    return HttpResponse(200, json.dumps({"status": "accepted"}))
                return HttpResponse(0, "")

            def request_grpc(self, host, port, rpc, string_fields=None,
                             varint_fields=None, timeout=6.0, delivery="standard"):
                fields = dict(string_fields or {})
                if rpc.endswith("/Health"):
                    return HttpResponse(200, "ok")
                if rpc.endswith("/ExportDiagnosticBundle") and "${FLAG}" in fields.get(1, ""):
                    return HttpResponse(
                        200,
                        "AegisD4HFLAG{finals_export_fixture}AegisD4H",
                    )
                return HttpResponse(200, "no flag")

        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(9000,),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="", concurrency=1,
        )
        arena = ExportArena()
        clk = FakeClock()
        report = AttackerRuntime(
            cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt)
        ).run_once()
        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{finals_export_fixture}")

    def test_satdiag_gateway_pivot_refreshes_http_endpoint_evidence(self):
        gateway_path = "/svc/flag-8ceb780e-e860-4078-8a1c-f5348976062f/"

        class GatewayArena:
            def __init__(self):
                self.target_paths = []
                self.submits = []

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                if url.endswith("/submit"):
                    self.submits.append(json.loads(body))
                    return HttpResponse(200, json.dumps({"status": "accepted"}))
                if "/v1/chat/completions" in url:
                    return HttpResponse(500, "unused")
                path = urlsplit(url).path
                self.target_paths.append(path)
                if path == gateway_path:
                    return HttpResponse(200, "FLAG{satdiag_gateway_pivot}")
                return HttpResponse(200, "portal online")

            def request_grpc(self, host, port, rpc, string_fields=None,
                             varint_fields=None, timeout=6.0, delivery="standard"):
                if rpc.endswith("/Health"):
                    return HttpResponse(
                        200,
                        json.dumps({"gateway_path": gateway_path}),
                    )
                return HttpResponse(200, "no flag")

        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(9000, 8080),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="", concurrency=1,
        )
        arena = GatewayArena()
        clk = FakeClock()
        report = AttackerRuntime(
            cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt)
        ).run_once()

        self.assertEqual(report.accepted_count(), 1)
        self.assertIn("/", arena.target_paths)
        self.assertIn(gateway_path, arena.target_paths)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{satdiag_gateway_pivot}")

    def test_finals_8080_runs_observed_fast_path_then_bounded_llm(self):
        class FinalsHttpArena:
            def __init__(self):
                self.target_paths = []
                self.llm_calls = 0
                self.llm_models = []

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                parts = urlsplit(url)
                if "/v1/chat/completions" in url:
                    self.llm_calls += 1
                    self.llm_models.append(json.loads(body).get("model"))
                    return HttpResponse(
                        200,
                        json.dumps({
                            "choices": [{"message": {
                                "content": '{"vuln":"OTHER","method":"GET","path":"/portal","headers":{},"body":"","reason":"probe"}'
                            }, "finish_reason": "stop"}],
                            "usage": {"total_tokens": 12},
                        }),
                    )
                self.target_paths.append(parts.path)
                if parts.path == "/":
                    return HttpResponse(303, "", {"Location": "/login"})
                return HttpResponse(404, "not found")

        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8080,),
            llm_base_url="http://litellm:4000", llm_api_key="sk-team1",
            concurrency=1,
        )
        arena = FinalsHttpArena()
        clk = FakeClock()
        report = AttackerRuntime(
            cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt)
        ).run_once()

        self.assertEqual(report.accepted_count(), 0)
        self.assertGreater(arena.llm_calls, 0)
        self.assertEqual(arena.llm_models, [DEFAULT_LLM_MODEL, DEFAULT_LLM_MODEL])
        self.assertIn("/fetch", arena.target_paths)
        self.assertIn("/config", arena.target_paths)
        self.assertIn("/portal", arena.target_paths)

    def test_unknown_l4_executes_llm_invented_route_under_pro_profile(self):
        arena = FakeArena(
            "Phase 4 UGV URL gateway online",
            "/invented?url=x",
            "irrelevant",
            flag_when=lambda full: False,
        )
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8085,),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_base_url="http://litellm:4000", llm_api_key="sk-team1",
            llm_model="gpt-4o-mini",
        )
        clk = FakeClock()
        report = AttackerRuntime(
            cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt)
        ).run_once()
        self.assertEqual(report.accepted_count(), 0)
        self.assertGreaterEqual(arena.llm_calls, 1)
        self.assertTrue(any(path.startswith("/invented") for path in arena.target_requests))

    def test_recon_captures_without_llm(self):
        # 흔한 경로 /flag 에서 flag → recon이 LLM 토큰 없이 획득
        arena = FakeArena("plain service", "/unused", "FLAG{recon_win}",
                          flag_when=lambda full: full.startswith("/flag"))
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8082,),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="",  # 키 없으면 결정론 성공 후 llm-skip
        )
        clk = FakeClock()
        rt = AttackerRuntime(cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt))
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{recon_win}")
        self.assertEqual(arena.llm_calls, 0)  # 토큰 0

    def test_llm_primary_runs_before_recon_hit_when_key_present(self):
        arena = FakeArena("plain service", "/unused", "FLAG{recon_win}",
                          flag_when=lambda full: full.startswith("/flag"))
        rt = make_runtime(arena)
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(arena.llm_calls, 2)

    def test_recon_collects_multiple_flags_from_one_service(self):
        class MultiFlagArena:
            def __init__(self):
                self.submits = []
                self.paths = []

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                if url.endswith("/submit"):
                    self.submits.append(json.loads(body))
                    return HttpResponse(200, json.dumps({"status": "accepted"}))
                if "/v1/chat/completions" in url:
                    return HttpResponse(500, "unused")
                parts = urlsplit(url)
                self.paths.append(parts.path)
                if parts.path == "/flag":
                    return HttpResponse(200, "FLAG{service_primary}")
                if parts.path == "/secret":
                    return HttpResponse(200, "FLAG{service_secondary}")
                return HttpResponse(200, "service online")

        arena = MultiFlagArena()
        rt = make_runtime(arena)
        report = rt.run_once()

        self.assertEqual(report.accepted_count(), 2)
        self.assertIn("/secret", arena.paths)
        self.assertEqual(
            {item["flag"] for item in arena.submits},
            {"FLAG{service_primary}", "FLAG{service_secondary}"},
        )

    def test_flag_in_notable_response_header_is_submitted(self):
        class HeaderFlagArena:
            def __init__(self):
                self.submits = []

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                if url.endswith("/submit"):
                    self.submits.append(json.loads(body))
                    return HttpResponse(200, json.dumps({"status": "accepted"}))
                if urlsplit(url).path == "/":
                    return HttpResponse(200, "service online", {"X-Flag": "FLAG{header_win}"})
                return HttpResponse(200, "online")

        arena = HeaderFlagArena()
        report = make_runtime(arena).run_once()

        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{header_win}")

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
    def test_stop_request_prevents_new_target_requests(self):
        arena = FakeArena("service", "/unused", "irrelevant")
        rt = make_runtime(arena)

        rt.request_stop()
        report = rt.run_once()

        self.assertEqual(arena.target_requests, [])
        self.assertEqual(report.summary()["requests_made"], 0)

    def test_run_forever_stops_at_round_deadline_and_wipes_secrets(self):
        class CycleOnlyRuntime(AttackerRuntime):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.cycles = 0

            def run_cycle(self):
                if not self._round_active:
                    raise RuntimeError("inactive Round")
                self.cycles += 1
                return self._report

        clk = FakeClock()
        sleeps = []

        def sleep(dt):
            sleeps.append(dt)
            clk.advance(dt)

        with patch("aegis_attacker.runtime.ROUND_DURATION", 5.0), \
             patch("aegis_attacker.runtime.LOOP_SLEEP", 4.0):
            rt = CycleOnlyRuntime(make_cfg(), http=FakeArena("b", "/x", "FLAG{x}"),
                                  clock=clk, sleep=sleep)
            rt.run_forever(max_cycles=3)

        self.assertEqual(rt.cycles, 2)
        self.assertEqual(sleeps, [4.0, 1.0])
        self.assertEqual(clk.t, 5.0)
        self.assertEqual(rt._secret_store.secrets_snapshot(), set())

    def test_run_forever_does_not_sleep_after_cycle_requests_stop(self):
        class StopAfterCycleRuntime(AttackerRuntime):
            def run_cycle(self):
                self.request_stop()
                return self._report

        clk = FakeClock()
        sleeps = []
        with patch("aegis_attacker.runtime.ROUND_DURATION", 5.0):
            rt = StopAfterCycleRuntime(
                make_cfg(), http=FakeArena("b", "/x", "FLAG{x}"),
                clock=clk, sleep=lambda dt: sleeps.append(dt),
            )
            rt.run_forever()

        self.assertEqual(sleeps, [])
        self.assertEqual(rt._secret_store.secrets_snapshot(), set())

    def test_run_forever_reuses_flag_store_across_scan_cycles(self):
        # 배너에 FLAG가 있으면 결정론 hit 후 LLM을 이어가므로, 이 테스트는 키 없이 토큰 0 경로만 본다.
        arena = FakeArena("FLAG{same_round}", "/x", "irrelevant")
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8082,),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="",
        )
        clk = FakeClock()
        rt = AttackerRuntime(cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt))
        rt.run_forever(max_cycles=2)
        self.assertEqual(len(arena.submits), 1)
        self.assertEqual(rt._report.summary()["submit_states"]["accepted"], 1)
        self.assertGreaterEqual(rt._report.summary()["requests_made"], 1)

    def test_unsolved_endpoint_waits_for_cooldown_without_new_playbook(self):
        arena = FakeArena(
            "plain service", "/never", "FLAG{never}",
            flag_when=lambda full: False, llm_status=500,
        )
        rt = make_runtime(arena)
        rt.start_round()
        try:
            rt.run_cycle()
            after_first = rt._report.summary()["requests_made"]
            rt.run_cycle()
            self.assertEqual(rt._report.summary()["requests_made"], after_first)
        finally:
            rt.finish_round()

    def test_startup_no_response_retries_before_a_short_scrimmage_ends(self):
        class LateServiceArena:
            def __init__(self):
                self.target_requests = 0
                self.passive_reads = 0

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                self.target_requests += 1
                return HttpResponse(0, "", {})

            def read_passive_banner(self, host, port, timeout, max_bytes):
                self.passive_reads += 1
                return HttpResponse(0, "", {})

        clk = FakeClock()
        arena = LateServiceArena()
        rt = AttackerRuntime(
            make_cfg(),
            http=arena,
            clock=clk,
            sleep=lambda dt: clk.advance(dt),
        )
        rt.start_round()
        try:
            rt.run_cycle()
            first_requests = rt._report.summary()["requests_made"]
            self.assertEqual(first_requests, 3)  # HTTP, HTTPS, passive TCP

            rt.run_cycle()
            self.assertEqual(rt._report.summary()["requests_made"], first_requests)

            clk.advance(BOOTSTRAP_RETRY_COOLDOWN)
            rt.run_cycle()
            self.assertGreater(rt._report.summary()["requests_made"], first_requests)
        finally:
            rt.finish_round()

    def test_unsolved_endpoint_retry_and_cooldown_are_auditable(self):
        arena = FakeArena(
            "plain service", "/never", "FLAG{never}",
            flag_when=lambda full: False, llm_status=500,
        )
        clk = FakeClock()
        lines = []
        rt = AttackerRuntime(
            make_cfg(), http=arena, clock=clk,
            sleep=lambda dt: clk.advance(dt),
            audit=AuditLogger(sink=lines.append, clock=clk),
        )
        with patch("aegis_attacker.runtime.PER_TARGET_BUDGET", 1):
            rt.start_round()
            try:
                rt.run_cycle()
                rt.run_cycle()
            finally:
                rt.finish_round()

        events = [json.loads(line) for line in lines]
        scheduled = [line for line in events if line["event"] == "endpoint-retry-scheduled"]
        deferred = [line for line in events if line["event"] == "endpoint-deferred"]
        self.assertEqual(len(scheduled), 1)
        self.assertEqual(scheduled[0]["reason"], "no-accepted-flag")
        self.assertEqual(scheduled[0]["cooldown_seconds"], 30.0)
        self.assertEqual(len(deferred), 1)
        self.assertEqual(deferred[0]["reason"], "cooldown")
        self.assertGreater(deferred[0]["remaining_seconds"], 0.0)

    def test_expired_evidence_is_refreshed_before_llm_plan_execution(self):
        clk = FakeClock()

        class SlowLlmArena(FakeArena):
            def request(self, method, url, headers=None, body=None, timeout=6.0):
                if "/v1/chat/completions" in url:
                    clk.advance(100.0)
                return super().request(method, url, headers, body, timeout)

        arena = SlowLlmArena(
            "plain service", "/magic", "FLAG{fresh_evidence}",
            flag_when=lambda full: full == "/magic",
        )
        rt = AttackerRuntime(
            make_cfg(), http=arena, clock=clk, sleep=lambda dt: clk.advance(dt)
        )
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{fresh_evidence}")

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
                          flag_when=lambda full: full.endswith("?url=x"))
        rt = make_runtime(arena)
        rt.run_once()
        after_first = rt.budget.llm_calls
        self.assertGreater(after_first, 0)  # 첫 라운드에서 LLM 예산을 소비
        rt.run_once()
        # 라운드별 예산은 격리되어야 한다: 누적(2N)이 아니라 라운드 단위(N)로 리셋
        self.assertEqual(rt.budget.llm_calls, after_first)
        self.assertEqual(rt._report.summary()["llm_calls"], after_first)

    def test_llm_model_and_turns_are_bounded(self):
        arena = FakeArena(
            "URL Fetcher — GET /fetch?url=<url>",
            "/fetch?url=miss",
            "FLAG{never}",
            flag_when=lambda full: False,
        )
        rt = make_runtime(arena)
        rt.run_once()
        self.assertEqual(arena.llm_models, ["gpt-4o-mini", "gpt-4o-mini"])


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
        # flag는 LLM이 만든 정확한 경로(?url=x)에서만 — 결정론 엔진의 내부 URL 시도와 구분
        if full.endswith("?url=x"):
            return HttpResponse(200, "FLAG{port_%s}" % parts.port)
        return HttpResponse(200, "no flag yet")


class ConcurrentDuplicateArena(FakeArena):
    """두 worker의 submit 진입을 barrier로 맞춰 중복 제출 경합을 재현한다."""

    def __init__(self):
        super().__init__("FLAG{shared}", "/unused", "irrelevant")
        self._submit_barrier = threading.Barrier(2)
        self._submit_lock = threading.Lock()

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        if not url.endswith("/submit"):
            return super().request(method, url, headers, body, timeout)
        with self._submit_lock:
            self.submits.append(json.loads(body))
        try:
            self._submit_barrier.wait(timeout=1.0)
        except threading.BrokenBarrierError:
            pass  # dedup이 동작하면 실제 submit caller는 하나뿐이다.
        return HttpResponse(200, json.dumps({"status": "accepted"}))


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
        self.assertGreaterEqual(arena.llm_calls, 1)  # 예산 소진 모드: 표적마다 LLM

    def test_dynamic_team_text_shares_structural_service_solver(self):
        class DynamicTeamArena:
            def __init__(self):
                self.llm_calls = 0
                self.submits = []
                self._lock = threading.Lock()

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                if url.endswith("/submit"):
                    with self._lock:
                        self.submits.append(json.loads(body))
                    return HttpResponse(200, json.dumps({"status": "accepted"}))
                if "/v1/chat/completions" in url:
                    with self._lock:
                        self.llm_calls += 1
                    content = json.dumps({
                        "vuln": "OTHER", "method": "GET",
                        "path": "/magic?probe=unlock", "headers": {}, "body": "",
                        "reason": "structural family solver",
                    })
                    return HttpResponse(200, json.dumps({
                        "choices": [{"message": {"content": content}}],
                        "usage": {"total_tokens": 10},
                    }))
                parts = urlsplit(url)
                if parts.path == "/" and not parts.query:
                    return HttpResponse(
                        200,
                        (f'<html><p>GET /magic?probe=&lt;value&gt;</p>'
                         f'<form action="/magic?probe=<value>">'
                         f'service for {parts.hostname}</form></html>'),
                        {"Content-Type": "text/html"},
                    )
                if parts.path == "/magic" and parts.query == "probe=unlock":
                    return HttpResponse(200, "FLAG{%s}" % parts.hostname.replace(".", "_"))
                return HttpResponse(200, "no flag")

        arena = DynamicTeamArena()
        cfg = AttackerConfig(
            targets=("team2.lig.internal", "team3.lig.internal"), ports=(9001,),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_base_url="http://litellm:4000", llm_api_key="sk-team1",
            llm_model="gpt-4o-mini", concurrency=2,
        )
        from aegis_attacker.rate_limit import RateLimiter
        rt = AttackerRuntime(
            cfg, http=arena, rate=RateLimiter(request_burst=10000, submit_max=10000)
        )
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 2)
        self.assertGreaterEqual(arena.llm_calls, 1)


class TestParallelAttack(unittest.TestCase):
    def test_same_flag_from_concurrent_endpoints_submits_once_per_round(self):
        arena = ConcurrentDuplicateArena()
        cfg = make_cfg(ports=(8082, 8083), concurrency=2)
        from aegis_attacker.rate_limit import RateLimiter
        rt = AttackerRuntime(cfg, http=arena,
                             rate=RateLimiter(request_burst=10000, submit_max=10000))

        rt.run_once()

        self.assertEqual(len(arena.submits), 1)

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
        # single-flight: 같은 배너이므로 LLM은 한 번만, 나머지 셋은 playbook 재사용(제22조)
        self.assertGreaterEqual(arena.llm_calls, 1)


class SsrfPivotArena:
    """/fetch?url= SSRF 아레나. 1단 /registry는 base64 내부 URL을, 그 URL은 flag를 준다.

    LLM 없이(키 공백) 결정론 엔진이 2단 피벗으로 flag를 뽑는지 검증한다.
    """

    def __init__(self, port):
        import base64
        self.submits = []
        self.llm_calls = 0
        self.port = port
        self._flag_url = "http://127.0.0.1:%d/vault" % port
        self._registry_b64 = base64.b64encode(self._flag_url.encode()).decode()

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        from urllib.parse import urlsplit, parse_qs, unquote
        if url.endswith("/submit"):
            self.submits.append(json.loads(body))
            return HttpResponse(200, json.dumps({"status": "accepted"}))
        if "/v1/chat/completions" in url:
            self.llm_calls += 1
            return HttpResponse(500, "should not be called")
        parts = urlsplit(url)
        if parts.path == "/" and not parts.query:
            return HttpResponse(200, "URL Fetcher — GET /fetch?url=<url>", {})
        if parts.path == "/fetch":
            target = unquote((parse_qs(parts.query).get("url") or [""])[0])
            if target.endswith("/registry"):
                return HttpResponse(200, "internal index: " + self._registry_b64, {})
            if target == self._flag_url:
                return HttpResponse(200, "FLAG{ssrf_pivot_%d}" % self.port, {})
            return HttpResponse(200, "unknown internal target", {})
        return HttpResponse(200, "no flag yet", {})


class TestDeterministicExploit(unittest.TestCase):
    def test_ssrf_two_stage_pivot_without_llm(self):
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8083,),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="",  # LLM 키 없음 — 결정론 엔진만으로 성공해야 함
        )
        arena = SsrfPivotArena(port=8083)
        clk = FakeClock()
        rt = AttackerRuntime(cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt))
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{ssrf_pivot_8083}")
        self.assertEqual(arena.llm_calls, 0)  # 토큰 0

    def test_two_ports_solved_deterministically_zero_llm(self):
        # 같은 배너의 두 포트를 결정론 엔진이 각각 토큰 0으로 잡는다(포트별 내부 URL 재유도)
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8083, 8084),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="",
        )

        class TwoPortSsrf(SsrfPivotArena):
            def __init__(self):
                super().__init__(port=8083)
                self._alt = SsrfPivotArena(port=8084)

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                from urllib.parse import urlsplit
                if ":8084" in urlsplit(url).netloc:
                    r = self._alt.request(method, url, headers, body, timeout)
                    if url.endswith("/submit"):
                        self.submits.append(json.loads(body))
                    return r
                return super().request(method, url, headers, body, timeout)

        arena = TwoPortSsrf()
        clk = FakeClock()
        rt = AttackerRuntime(cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt))
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 2)
        self.assertEqual(arena.llm_calls, 0)


class AdminHeaderArena:
    """/admin 인증 우회: X-Role: admin 헤더가 있어야 flag. LLM만 이 헤더를 만든다.

    같은 배너의 여러 포트에서 첫 포트만 LLM으로 풀고, 나머지는 헤더까지 담긴 playbook을
    재사용해 토큰 0으로 잡는지(헤더 보존 회귀 방지) 검증한다.
    """

    def __init__(self):
        self.submits = []
        self.llm_calls = 0
        self._lock = threading.Lock()

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        if url.endswith("/submit"):
            with self._lock:
                self.submits.append(json.loads(body))
            return HttpResponse(200, json.dumps({"status": "accepted"}))
        if "/v1/chat/completions" in url:
            with self._lock:
                self.llm_calls += 1
            # 결정론 기본셋에 없는 비표준 헤더 — LLM만 이걸 만든다
            content = json.dumps({"vuln": "AUTH", "method": "GET", "path": "/admin",
                                  "headers": {"X-Backdoor": "1"}, "body": "",
                                  "reason": "auth header"})
            return HttpResponse(200, json.dumps({
                "choices": [{"message": {"content": content}}],
                "usage": {"total_tokens": 10}}))
        parts = urlsplit(url)
        if parts.path == "/" and not parts.query:
            return HttpResponse(200, "Service online v2", {})  # 인증 키워드 없는 중립 배너
        if parts.path == "/admin":
            if (headers or {}).get("X-Backdoor", "") == "1":
                return HttpResponse(200, "FLAG{admin_%s}" % (parts.port or "x"), {})
            return HttpResponse(403, "forbidden", {})
        return HttpResponse(200, "no flag yet", {})


class TestHeaderExploitReuse(unittest.TestCase):
    def test_admin_header_exploit_reused_across_ports_one_llm_call(self):
        arena = AdminHeaderArena()
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8082, 8083, 8084),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_base_url="http://litellm:4000", llm_api_key="sk-team1",
            llm_model="gpt-4o-mini", concurrency=3)
        from aegis_attacker.rate_limit import RateLimiter
        rt = AttackerRuntime(cfg, http=arena,
                             rate=RateLimiter(request_burst=10000, submit_max=10000))
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 3)          # 세 포트 모두 flag
        self.assertGreaterEqual(arena.llm_calls, 1)  # 예산 소진: 포트마다 LLM


class RateLimitedSsrfArena:
    """표적이 N개 요청 후 응답을 끊는다(rate-limit 차단 모사).

    SSRF 피벗이 base sweep 끝이 아니라 /registry 직후 즉시 돌아야 차단 전에 flag를 잡는다.
    """

    def __init__(self, port, block_after):
        import base64
        self.port = port
        self.block_after = block_after
        self.target_reqs = 0
        self.submits = []
        self.llm_calls = 0
        self._flag_url = "http://127.0.0.1:%d/vault" % port
        self._registry_b64 = base64.b64encode(self._flag_url.encode()).decode()

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        from urllib.parse import urlsplit, parse_qs, unquote
        if url.endswith("/submit"):
            self.submits.append(json.loads(body))
            return HttpResponse(200, json.dumps({"status": "accepted"}))
        if "/v1/chat/completions" in url:
            self.llm_calls += 1
            return HttpResponse(500, "no llm")
        parts = urlsplit(url)
        self.target_reqs += 1
        if self.target_reqs > self.block_after:
            return HttpResponse(0, "")  # 표적이 차단(무응답)
        if parts.path == "/" and not parts.query:
            return HttpResponse(200, "URL Fetcher — GET /fetch?url=<url>", {})
        if parts.path == "/fetch":
            target = unquote((parse_qs(parts.query).get("url") or [""])[0])
            if target.endswith("/registry"):
                return HttpResponse(200, "index: " + self._registry_b64, {})
            if target == self._flag_url:
                return HttpResponse(200, "FLAG{early_pivot_%d}" % self.port, {})
            return HttpResponse(200, "unknown", {})
        return HttpResponse(200, "no flag", {})


class TestPivotBeforeRateLimit(unittest.TestCase):
    def test_pivot_fires_before_target_blocks(self):
        # 표적이 20 요청 후 차단. 피벗이 /registry 직후 즉시 돌아야 그 전에 flag를 잡는다.
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8083,),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="",
        )
        arena = RateLimitedSsrfArena(port=8083, block_after=20)
        clk = FakeClock()
        rt = AttackerRuntime(cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt))
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{early_pivot_8083}")
        self.assertEqual(arena.llm_calls, 0)


class ObservedPhaseArena:
    """TEAM1 PCAP에서 확인된 L1~L3 fast path를 포트별로 재현한다."""

    def __init__(self):
        self.submits = []
        self.llm_calls = 0

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        from urllib.parse import parse_qs, unquote, urlsplit

        if url.endswith("/submit"):
            self.submits.append(json.loads(body))
            return HttpResponse(200, json.dumps({"status": "accepted"}))
        if "/v1/chat/completions" in url:
            self.llm_calls += 1
            return HttpResponse(500, "unused")

        parts = urlsplit(url)
        if parts.path == "/" and not parts.query:
            return HttpResponse(200, "service online", {})
        params = parse_qs(parts.query)

        if parts.port == 8080 and parts.path in ("/fetch", "/proxy"):
            target = unquote(next(iter(params.values()), [""])[0])
            if target in (
                "http://helper-box:8080/secret",
                "http://helper-box.:8080/secret",
            ):
                return HttpResponse(200, "FLAG{fixture_l1}", {})

        if parts.port == 8082 and parts.path == "/graphql" and body:
            if "missionAudit" in body:
                return HttpResponse(200, "FLAG{fixture_l2}", {})

        if parts.port == 8082 and parts.path == "/admin":
            cookie = (headers or {}).get("Cookie", "")
            _, _, token = cookie.partition("session=")
            try:
                padded = token + "=" * (-len(token) % 4)
                claims = json.loads(base64.urlsafe_b64decode(padded))
            except Exception:
                claims = {}
            if claims.get("role") == "admin":
                return HttpResponse(200, "FLAG{fixture_l2}", {})

        if parts.port == 9090 and parts.path == "/product":
            product_id = unquote((params.get("id") or [""])[0]).lower()
            if "union select" in product_id and "from app_meta" in product_id:
                return HttpResponse(200, "FLAG{fixture_l3}", {})

        return HttpResponse(200, "no flag", {})


class TestObservedPhaseFastPath(unittest.TestCase):
    def test_l1_to_l3_confirmed_vectors_run_before_llm(self):
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8080, 8082, 9090),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="", concurrency=3,
        )
        from aegis_attacker.rate_limit import RateLimiter
        arena = ObservedPhaseArena()
        rt = AttackerRuntime(
            cfg,
            http=arena,
            rate=RateLimiter(request_burst=10000, submit_max=10000),
        )
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 3)
        self.assertEqual(arena.llm_calls, 0)


class UgvDiscoveryArena:
    """L4 route를 root가 아니라 읽기 전용 /status 응답에서만 노출한다."""

    def __init__(self):
        self.submits = []
        self.llm_calls = 0
        self.target_requests = []

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        from urllib.parse import parse_qs, unquote, urlsplit

        if url.endswith("/submit"):
            self.submits.append(json.loads(body))
            return HttpResponse(200, json.dumps({"status": "accepted"}))
        if "/v1/chat/completions" in url:
            self.llm_calls += 1
            return HttpResponse(500, "unused")

        parts = urlsplit(url)
        self.target_requests.append(parts.path + (("?" + parts.query) if parts.query else ""))
        if parts.path == "/" and not parts.query:
            return HttpResponse(200, "Phase 4 UGV online", {})
        if parts.path == "/status":
            return HttpResponse(200, "Routes: GET /telemetry?source=<url>", {})
        if parts.path == "/telemetry":
            target = unquote((parse_qs(parts.query).get("source") or [""])[0])
            if target == "http://127.0.0.1:8085/registry":
                return HttpResponse(200, "FLAG{fixture_l4}", {})
        return HttpResponse(200, "online", {})


class TestUgvObservedDiscovery(unittest.TestCase):
    def test_phase4_uses_status_exposed_route_without_hardcoded_ugv_path(self):
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8085,),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="", concurrency=1,
        )
        arena = UgvDiscoveryArena()
        clk = FakeClock()
        rt = AttackerRuntime(cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt))
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{fixture_l4}")
        self.assertEqual(arena.llm_calls, 0)
        exploit_queries = [path for path in arena.target_requests if "?" in path]
        self.assertTrue(exploit_queries)
        self.assertTrue(all(path.startswith("/telemetry?source=") for path in exploit_queries))
        self.assertNotIn("/flag", arena.target_requests)
        self.assertNotIn("/admin", arena.target_requests)
        self.assertNotIn("/.git/config", arena.target_requests)

    def test_multiple_l4_ports_keep_routes_scoped_and_collect_multiple_flags(self):
        class MultiServiceUgvArena:
            def __init__(self):
                self.submits = []
                self.llm_calls = 0
                self.target_requests = {9001: [], 9002: []}

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                from urllib.parse import parse_qs, unquote, urlsplit

                if url.endswith("/submit"):
                    self.submits.append(json.loads(body))
                    return HttpResponse(200, json.dumps({"status": "accepted"}))
                if "/v1/chat/completions" in url:
                    self.llm_calls += 1
                    return HttpResponse(500, "unused")

                parts = urlsplit(url)
                port = parts.port
                full = parts.path + (("?" + parts.query) if parts.query else "")
                self.target_requests[port].append(full)
                if parts.path == "/" and not parts.query:
                    return HttpResponse(200, "Phase 4 service online", {})
                if parts.path == "/status":
                    if port == 9001:
                        return HttpResponse(200, "GET /telemetry?source=<url>", {})
                    return HttpResponse(200, "GET /inspect?uri=<url>", {})

                params = parse_qs(parts.query)
                if port == 9001 and parts.path == "/telemetry":
                    target = unquote((params.get("source") or [""])[0])
                    if target == "http://127.0.0.1:9001/registry":
                        return HttpResponse(200, "FLAG{synthetic_l4_service_a}", {})
                if port == 9002 and parts.path == "/inspect":
                    target = unquote((params.get("uri") or [""])[0])
                    if target == "http://127.0.0.1:9002/registry":
                        return HttpResponse(200, "FLAG{synthetic_l4_service_b}", {})
                return HttpResponse(200, "online", {})

        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(9001, 9002),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="", concurrency=2,
        )
        from aegis_attacker.rate_limit import RateLimiter
        arena = MultiServiceUgvArena()
        rt = AttackerRuntime(
            cfg,
            http=arena,
            rate=RateLimiter(request_burst=10000, submit_max=10000),
        )

        report = rt.run_once()

        self.assertEqual(report.accepted_count(), 2)
        self.assertEqual(len(arena.submits), 2)
        self.assertEqual(arena.llm_calls, 0)
        self.assertTrue(any(path.startswith("/telemetry?source=")
                            for path in arena.target_requests[9001]))
        self.assertFalse(any(path.startswith("/inspect?")
                             for path in arena.target_requests[9001]))
        self.assertTrue(any(path.startswith("/inspect?uri=")
                            for path in arena.target_requests[9002]))
        self.assertFalse(any(path.startswith("/telemetry?")
                             for path in arena.target_requests[9002]))
        for requests in arena.target_requests.values():
            self.assertNotIn("/flag", requests)
            self.assertNotIn("/admin", requests)
            self.assertNotIn("/.git/config", requests)

    def test_https_only_l4_uses_observed_route_and_collects_multiple_flags(self):
        class HttpsUgvArena:
            def __init__(self):
                self.submits = []
                self.target_urls = []
                self.llm_calls = 0

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                from urllib.parse import parse_qs, unquote, urlsplit

                if url.endswith("/submit"):
                    self.submits.append(json.loads(body))
                    return HttpResponse(200, json.dumps({"status": "accepted"}))
                if "/v1/chat/completions" in url:
                    self.llm_calls += 1
                    return HttpResponse(500, "unused")
                self.target_urls.append(url)
                parts = urlsplit(url)
                if parts.scheme == "http":
                    return HttpResponse(0, "", {})
                if parts.path == "/":
                    return HttpResponse(200, "secure Phase 4 service", {})
                if parts.path == "/status":
                    return HttpResponse(200, "GET /inspect?uri=<url>", {})
                if parts.path == "/inspect":
                    target = unquote((parse_qs(parts.query).get("uri") or [""])[0])
                    if target == "http://127.0.0.1:9443/registry":
                        return HttpResponse(
                            200,
                            "FLAG{synthetic_https_l4_a} FLAG{synthetic_https_l4_b}",
                            {},
                        )
                return HttpResponse(200, "online", {})

        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(9443,),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="", concurrency=1,
        )
        arena = HttpsUgvArena()
        clk = FakeClock()
        report = AttackerRuntime(
            cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt)
        ).run_once()

        self.assertEqual(report.accepted_count(), 2)
        self.assertEqual(len(arena.submits), 2)
        self.assertEqual(arena.llm_calls, 0)
        self.assertTrue(arena.target_urls[0].startswith("http://"))
        self.assertTrue(all(url.startswith("https://") for url in arena.target_urls[1:]))

    def test_non_http_l4_passive_banner_collects_flag_without_client_payload(self):
        class PassiveBannerArena:
            def __init__(self):
                self.submits = []
                self.http_calls = []
                self.banner_calls = []
                self.llm_calls = 0

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                if url.endswith("/submit"):
                    self.submits.append(json.loads(body))
                    return HttpResponse(200, json.dumps({"status": "accepted"}))
                if "/v1/chat/completions" in url:
                    self.llm_calls += 1
                    return HttpResponse(500, "unused")
                self.http_calls.append((method, url, body))
                return HttpResponse(0, "", {})

            def read_passive_banner(self, host, port, timeout, max_bytes):
                self.banner_calls.append((host, port, timeout, max_bytes))
                return HttpResponse(200, "FLAG{synthetic_passive_tcp_l4}", {})

        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(9100,),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="", concurrency=1,
        )
        arena = PassiveBannerArena()
        clk = FakeClock()
        report = AttackerRuntime(
            cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt)
        ).run_once()

        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(len(arena.submits), 1)
        self.assertEqual(len(arena.http_calls), 2)
        self.assertTrue(all(body is None for _, _, body in arena.http_calls))
        self.assertEqual(len(arena.banner_calls), 1)
        self.assertLessEqual(arena.banner_calls[0][2], 0.75)
        self.assertLessEqual(arena.banner_calls[0][3], 4096)
        self.assertEqual(arena.llm_calls, 0)


class TestRuntimeInert(unittest.TestCase):
    def test_inert_without_targets_returns(self):
        cfg = AttackerConfig(targets=(), ports=(), llm_api_key="sk")
        logs = []
        from aegis_attacker.audit import AuditLogger
        rt = AttackerRuntime(cfg, http=FakeArena("b", "/x", "f"),
                             audit=AuditLogger(sink=logs.append))
        rt.run_forever()
        self.assertTrue(any("inert" in line for line in logs))

    def test_recon_fetch_without_llm_key(self):
        cfg = AttackerConfig(
            targets=("t2.lig.internal",), ports=(8082,),
            submit_url="http://backend:4100/submit", submit_token="tok-team1",
            llm_api_key="",
        )
        arena = FakeArena("URL Fetcher", "/unused", "FLAG{fetch_win}",
                          flag_when=lambda full: full == "/fetch")
        clk = FakeClock()
        rt = AttackerRuntime(cfg, http=arena, clock=clk, sleep=lambda dt: clk.advance(dt))
        report = rt.run_once()
        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(arena.submits[0]["flag"], "FLAG{fetch_win}")
        self.assertEqual(arena.llm_calls, 0)


if __name__ == "__main__":
    unittest.main()
