import json
import unittest

from aegis_attacker.config import AttackerConfig
from aegis_attacker.observation import HttpResponse
from aegis_attacker.runtime import AttackerRuntime


class ProtocolArena:
    def __init__(self):
        self.mqtt_calls = []
        self.rtsp_calls = []
        self.http_target_calls = []
        self.submits = []

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        if url.endswith("/submit"):
            self.submits.append(json.loads(body))
            return HttpResponse(200, json.dumps({"status": "accepted"}))
        self.http_target_calls.append((method, url))
        return HttpResponse(0, "")

    def request_mqtt(self, host, port, topics=(), timeout=3.0):
        self.mqtt_calls.append((host, port, tuple(topics)))
        if topics:
            return HttpResponse(200, "uav/status FLAG{mqtt-runtime}")
        return HttpResponse(200, "MQTT CONNACK")

    def request_rtsp(self, host, port, method, path, timeout=3.0):
        self.rtsp_calls.append((host, port, method, path))
        if method == "DESCRIBE" and path == "/live":
            return HttpResponse(200, "a=x-flag:FLAG{rtsp-runtime}")
        return HttpResponse(200, "RTSP/1.0 200 OK")


def config(port):
    return AttackerConfig(
        targets=("team2",),
        ports=(port,),
        submit_url="http://backend:4100/submit",
        submit_token="token",
        llm_api_key="",
        concurrency=1,
    )


class TestProtocolRuntime(unittest.TestCase):
    def test_mqtt_endpoint_uses_protocol_path_and_submits_flag(self):
        arena = ProtocolArena()
        report = AttackerRuntime(config(1883), http=arena).run_once()

        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(arena.mqtt_calls[0][2], ())
        # R8: exact config topic first; FLAG hit이면 wildcard batch는 생략한다.
        self.assertEqual(arena.mqtt_calls[1][2], ("uav/node/config",))
        self.assertEqual(arena.http_target_calls, [])
        self.assertEqual(arena.submits[0]["flag"], "FLAG{mqtt-runtime}")

    def test_rtsp_endpoint_only_uses_options_and_describe(self):
        arena = ProtocolArena()
        report = AttackerRuntime(config(8554), http=arena).run_once()

        self.assertEqual(report.accepted_count(), 1)
        self.assertEqual(arena.rtsp_calls[0][2:], ("OPTIONS", "*"))
        self.assertTrue(all(call[2] in {"OPTIONS", "DESCRIBE"} for call in arena.rtsp_calls))
        self.assertEqual(arena.http_target_calls, [])
        self.assertEqual(arena.submits[0]["flag"], "FLAG{rtsp-runtime}")

    def test_silent_protocol_ports_do_not_fall_through_to_http(self):
        class SilentProtocolArena(ProtocolArena):
            def request_mqtt(self, host, port, topics=(), timeout=3.0):
                self.mqtt_calls.append((host, port, tuple(topics)))
                return HttpResponse(0, "")

            def request_rtsp(self, host, port, method, path, timeout=3.0):
                self.rtsp_calls.append((host, port, method, path))
                return HttpResponse(0, "")

        for port in (1883, 8554, 9000):
            with self.subTest(port=port):
                arena = SilentProtocolArena()
                AttackerRuntime(config(port), http=arena).run_once()
                self.assertEqual(arena.http_target_calls, [])


if __name__ == "__main__":
    unittest.main()
