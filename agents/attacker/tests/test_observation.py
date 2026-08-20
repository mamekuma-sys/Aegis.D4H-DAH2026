import socket
import threading
import unittest

from aegis_attacker.config import AttackerConfig
from aegis_attacker.egress import EgressGateway, build_allowlists
from aegis_attacker.models import Endpoint
from aegis_attacker.observation import (
    HttpResponse,
    MAX_RESPONSE_BYTES,
    Observer,
    UrllibHttp,
    fingerprint,
    notable_headers,
)
from aegis_attacker.rate_limit import RateLimiter

EP = Endpoint("team2.lig.internal", 8082)
CFG = AttackerConfig(targets=("team2.lig.internal",), ports=(8082,), llm_api_key="k")


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class FakeTransport:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        self.calls.append((method, url, headers, body, timeout))
        return self.response


class TestHelpers(unittest.TestCase):
    def test_fingerprint_stable_and_no_plaintext(self):
        fp = fingerprint("FLAG{secret}")
        self.assertEqual(len(fp), 16)
        self.assertNotIn("FLAG", fp)
        self.assertEqual(fp, fingerprint("FLAG{secret}"))

    def test_notable_headers_filter(self):
        h = {"Set-Cookie": "s=1", "Content-Type": "text/html", "X-Role": "user"}
        picked = notable_headers(h)
        self.assertIn("Set-Cookie", picked)
        self.assertIn("X-Role", picked)
        self.assertNotIn("Content-Type", picked)


class TestBoundedTransport(unittest.TestCase):
    def test_response_body_is_capped_at_one_megabyte(self):
        class Response:
            status = 200
            headers = {"Content-Type": "text/plain"}

            def __init__(self):
                self.requested = None

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, size=-1):
                self.requested = size
                return b"x" * size

        class Opener:
            def __init__(self, response):
                self.response = response

            def open(self, _request, timeout):
                return self.response

        response = Response()
        transport = UrllibHttp()
        transport._opener = Opener(response)

        result = transport.request("GET", "http://example.invalid/")

        self.assertEqual(response.requested, MAX_RESPONSE_BYTES + 1)
        self.assertEqual(len(result.body), MAX_RESPONSE_BYTES)
        self.assertTrue(result.truncated)

    def test_passive_tcp_banner_reads_bounded_server_bytes_without_client_write(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        received = []

        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.sendall(b"x" * 5000)
                    connection.settimeout(1.0)
                    try:
                        received.append(connection.recv(1))
                    except ConnectionResetError:
                        # Windows closes a socket with unread server bytes using RST.
                        # RST still proves that no client application byte arrived.
                        received.append(b"")
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        response = UrllibHttp.read_passive_banner(
            "127.0.0.1", port, timeout=0.75, max_bytes=4096
        )
        thread.join(timeout=2.0)

        self.assertEqual(response.status, 200)
        self.assertEqual(len(response.body), 4096)
        self.assertTrue(response.truncated)
        self.assertEqual(received, [b""])


class TestObserver(unittest.TestCase):
    def _observer(self, resp):
        clk = FakeClock()
        rl = RateLimiter(clock=clk, sleep=lambda dt: clk.advance(dt))
        gw = EgressGateway(FakeTransport(resp), build_allowlists(CFG))
        return Observer(gw, rl, round_id="r1", clock=clk), clk

    def test_observe_banner_builds_observation(self):
        obs_er, _ = self._observer(HttpResponse(200, "URL Fetcher", {"Server": "Werkzeug"}))
        obs, resp = obs_er.observe_banner(EP)
        self.assertEqual(obs.status, 200)
        self.assertEqual(resp.body, "URL Fetcher")
        self.assertIn("Server", obs.redacted_header_hints)
        self.assertEqual(obs.round_id, "r1")
        self.assertIsNotNone(obs.evidence_ref)  # 증거 참조 부착
        self.assertTrue(obs.evidence_ref.valid_at(0.0, "r1", EP.endpoint_id))
        self.assertFalse(obs.no_response)

    def test_no_response_recorded_as_observation(self):
        obs_er, _ = self._observer(HttpResponse(0, "", {}))
        obs, _ = obs_er.observe_banner(EP)
        self.assertTrue(obs.no_response)
        self.assertEqual(obs.note, "no-response")

    def test_observe_respects_rate_limit(self):
        obs_er, _ = self._observer(HttpResponse(200, "ok", {}))
        for _ in range(25):
            obs_er.observe_banner(EP)

    def test_adaptive_banner_falls_back_to_https_only_after_http_no_response(self):
        class SchemeTransport:
            def __init__(self):
                self.calls = []

            def request(self, method, url, headers=None, body=None, timeout=6.0):
                self.calls.append(url)
                if url.startswith("https://"):
                    return HttpResponse(200, "secure service", {})
                return HttpResponse(0, "", {})

        clk = FakeClock()
        transport = SchemeTransport()
        observer = Observer(
            EgressGateway(transport, build_allowlists(CFG)),
            RateLimiter(clock=clk, sleep=lambda dt: clk.advance(dt)),
            round_id="r1",
            clock=clk,
        )

        obs, resp, selected, attempts = observer.observe_banner_adaptive(EP)

        self.assertEqual(obs.status, 200)
        self.assertEqual(resp.body, "secure service")
        self.assertEqual(selected.scheme, "https")
        self.assertEqual(attempts, 2)
        self.assertEqual(
            transport.calls,
            ["http://team2.lig.internal:8082/", "https://team2.lig.internal:8082/"],
        )


if __name__ == "__main__":
    unittest.main()
