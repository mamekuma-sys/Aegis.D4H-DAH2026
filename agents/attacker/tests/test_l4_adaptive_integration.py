"""독립 합성 L4 arena에서 adaptive transport를 실제 loopback I/O로 검증한다."""

import json
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from aegis_attacker.config import AttackerConfig
from aegis_attacker.rate_limit import RateLimiter
from aegis_attacker.runtime import AttackerRuntime


class _QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def _reply(self, body, status=200):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _L4Handler(_QuietHandler):
    service_port = 0

    def do_GET(self):
        target = urlsplit(self.path)
        if target.path == "/":
            return self._reply("Phase 4 synthetic multi-flag service")
        if target.path == "/status":
            return self._reply("GET /inspect?uri=<url>")
        if target.path == "/inspect":
            value = unquote((parse_qs(target.query).get("uri") or [""])[0])
            if value == f"http://127.0.0.1:{self.service_port}/registry":
                return self._reply(
                    "FLAG{synthetic_l4_integration_a} FLAG{synthetic_l4_integration_b}"
                )
        return self._reply("online")


class _SubmitHandler(_QuietHandler):
    submissions = []
    lock = threading.Lock()

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        document = json.loads(self.rfile.read(size))
        with self.lock:
            self.submissions.append(document["flag"])
        self._reply(json.dumps({"status": "accepted"}))


class _PassiveBannerServer:
    """HTTP, TLS, passive read의 세 연결에 같은 서버 주도 banner를 보낸다."""

    def __init__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(3)
        self.port = self.listener.getsockname()[1]
        self.client_bytes = []
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def _serve(self):
        try:
            for _ in range(3):
                connection, _ = self.listener.accept()
                with connection:
                    connection.sendall(b"FLAG{synthetic_l4_passive_integration}")
                    connection.settimeout(1.0)
                    try:
                        self.client_bytes.append(connection.recv(4096))
                    except (ConnectionResetError, socket.timeout):
                        self.client_bytes.append(b"")
        finally:
            self.listener.close()

    def stop(self):
        self.thread.join(timeout=4.0)


class TestL4AdaptiveIntegration(unittest.TestCase):
    def test_real_loopback_multi_service_multi_flag_zero_llm(self):
        _SubmitHandler.submissions = []
        l4 = ThreadingHTTPServer(("127.0.0.1", 0), _L4Handler)
        submit = ThreadingHTTPServer(("127.0.0.1", 0), _SubmitHandler)
        _L4Handler.service_port = l4.server_address[1]
        passive = _PassiveBannerServer()
        threads = [
            threading.Thread(target=l4.serve_forever, daemon=True),
            threading.Thread(target=submit.serve_forever, daemon=True),
        ]
        for thread in threads:
            thread.start()
        passive.start()

        try:
            config = AttackerConfig(
                targets=("127.0.0.1",),
                ports=(l4.server_address[1], passive.port),
                submit_url=f"http://127.0.0.1:{submit.server_address[1]}/submit",
                submit_token="synthetic-submit-token",
                llm_api_key="",
                concurrency=2,
            )
            runtime = AttackerRuntime(
                config,
                rate=RateLimiter(request_burst=10000, submit_max=10000),
            )

            report = runtime.run_once()

            self.assertEqual(report.accepted_count(), 3)
            self.assertEqual(len(_SubmitHandler.submissions), 3)
            self.assertEqual(report.summary()["llm_calls"], 0)
            self.assertEqual(len(passive.client_bytes), 3)
            self.assertTrue(passive.client_bytes[0].startswith(b"GET "))
            self.assertTrue(passive.client_bytes[1])  # TLS ClientHello
            self.assertEqual(passive.client_bytes[2], b"")  # passive 단계는 write 0
        finally:
            l4.shutdown()
            submit.shutdown()
            l4.server_close()
            submit.server_close()
            passive.stop()
            for thread in threads:
                thread.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
