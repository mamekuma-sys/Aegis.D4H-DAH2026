import unittest

from aegis_attacker.config import AttackerConfig
from aegis_attacker.egress import EgressError, EgressGateway, build_allowlists
from aegis_attacker.models import Capability
from aegis_attacker.observation import HttpResponse


class RecordingTransport:
    def __init__(self):
        self.calls = []

    def request_mqtt(self, host, port, topics, timeout):
        self.calls.append(("mqtt", host, port, topics))
        return HttpResponse(200, "ok")

    def request_rtsp(self, host, port, method, path, timeout):
        self.calls.append(("rtsp", host, port, method, path))
        return HttpResponse(200, "ok")


class TestProtocolEgress(unittest.TestCase):
    def setUp(self):
        config = AttackerConfig(targets=("team2",), ports=(1883, 8554))
        self.transport = RecordingTransport()
        self.gateway = EgressGateway(self.transport, build_allowlists(config))

    def test_mqtt_read_topics_are_allowlisted(self):
        self.gateway.request_mqtt(
            Capability.ATTACK_TARGET, "team2", 1883, ("#", "$SYS/#")
        )
        with self.assertRaises(EgressError):
            self.gateway.request_mqtt(
                Capability.ATTACK_TARGET, "team2", 1883, ("control/cmd",)
            )
        with self.assertRaises(EgressError):
            self.gateway.request_mqtt(
                Capability.ATTACK_TARGET, "other", 1883, ("#",)
            )
        self.assertEqual(len(self.transport.calls), 1)

    def test_rtsp_mutating_or_unknown_requests_are_rejected(self):
        self.gateway.request_rtsp(
            Capability.ATTACK_TARGET, "team2", 8554, "DESCRIBE", "/live"
        )
        with self.assertRaises(EgressError):
            self.gateway.request_rtsp(
                Capability.ATTACK_TARGET, "team2", 8554, "PLAY", "/live"
            )
        with self.assertRaises(EgressError):
            self.gateway.request_rtsp(
                Capability.ATTACK_TARGET, "team2", 8554, "DESCRIBE", "/control"
            )
        with self.assertRaises(EgressError):
            self.gateway.request_rtsp(
                Capability.LLM, "team2", 8554, "OPTIONS", "*"
            )
        self.assertEqual(len(self.transport.calls), 1)


if __name__ == "__main__":
    unittest.main()
