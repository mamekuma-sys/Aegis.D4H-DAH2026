import os
import unittest

from aegis_defender.packet import parse_ip
from aegis_defender.policy import HotPolicy, R_ACCEPT_DEFAULT, R_SHADOW
from aegis_defender.protocol import VERDICT_ACCEPT
from aegis_defender.rules import load_policy

from .fakes import ipv4_tcp

_POLICY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policy"))
_ACTIVE_WINDOW_EPOCH = 1787356800.0


class TestL3ProtocolPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled, cls.report = load_policy(
            _POLICY_DIR, now_epoch=_ACTIVE_WINDOW_EPOCH
        )

    def _decide(self, payload, port):
        policy = HotPolicy(policy=self.compiled, clock=lambda: 0.0)
        return policy.decide(1, parse_ip(ipv4_tcp(payload, dst_port=port)), 0.0)

    def test_mqtt_wildcard_subscribe_is_observed_without_drop(self):
        # SUBSCRIBE, packet id 1, topic filter '#', QoS 0.
        payload = b"\x82\x06\x00\x01\x00\x01#\x00"
        decision = self._decide(payload, 1883)

        self.assertEqual(decision.verdict, VERDICT_ACCEPT)
        self.assertEqual(decision.reason_code, R_SHADOW)
        self.assertEqual(decision.rule_id, "sig-l3-mqtt-wildcard-subscribe-001")

    def test_mqtt_connect_is_normal_default_accept(self):
        decision = self._decide(b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x05\x00\x00", 1883)
        self.assertEqual(decision.verdict, VERDICT_ACCEPT)
        self.assertEqual(decision.reason_code, R_ACCEPT_DEFAULT)

    def test_rtsp_sensitive_describe_is_observed_without_drop(self):
        payload = (
            b"DESCRIBE rtsp://uav-node:8554/flag RTSP/1.0\r\n"
            b"CSeq: 1\r\n\r\n"
        )
        decision = self._decide(payload, 8554)

        self.assertEqual(decision.verdict, VERDICT_ACCEPT)
        self.assertEqual(decision.reason_code, R_SHADOW)
        self.assertEqual(decision.rule_id, "sig-l3-rtsp-sensitive-describe-001")

    def test_rtsp_live_describe_is_normal_default_accept(self):
        payload = b"DESCRIBE rtsp://uav-node:8554/live RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        decision = self._decide(payload, 8554)
        self.assertEqual(decision.verdict, VERDICT_ACCEPT)
        self.assertEqual(decision.reason_code, R_ACCEPT_DEFAULT)


if __name__ == "__main__":
    unittest.main()
