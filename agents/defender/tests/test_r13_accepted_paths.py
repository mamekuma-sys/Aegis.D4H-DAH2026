"""P4 R13 attacker accepted 경로를 현재 ACTIVE policy로 묶어 검증한다."""

import os
import unittest

from aegis_defender.packet import parse_ip
from aegis_defender.policy import HotPolicy
from aegis_defender.protocol import VERDICT_DROP
from aegis_defender.rules import load_policy

from .fakes import ipv4_tcp

_POLICY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policy"))
_ACTIVE_WINDOW_EPOCH = 1787356800.0


class TestR13AcceptedPathCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled, _ = load_policy(_POLICY_DIR, now_epoch=_ACTIVE_WINDOW_EPOCH)

    def test_all_six_r13_accepted_attempts_are_now_active_drops(self):
        cases = (
            (
                "mqtt-wildcard",
                1883,
                b"\x82\x06\x00\x01\x00\x01#\x00",
                "sig-l3-mqtt-wildcard-subscribe-001",
            ),
            (
                "mqtt-exact-config",
                1883,
                b"uav/node/config",
                "sig-l3-mqtt-uav-config-001",
            ),
            (
                "satdiag-tail",
                9000,
                b":path*/satdiag.v1.SatDiag/TailDiagnosticLog\x00\x0a\x05/flag",
                "sig-l1-satdiag-tail-flag-001",
            ),
            (
                "satdiag-export",
                9000,
                b":path*/satdiag.v1.SatDiag/ExportDiagnosticBundle\x00"
                b"telemetry.log;echo M${FLAG}M\x12\x07capture",
                "sig-l1-satdiag-export-flag-echo-001",
            ),
            (
                "l2-rsc",
                8082,
                b"POST /api/rsc-action HTTP/1.1\r\nHost: x\r\n"
                b"Content-Type: application/json\r\n\r\n"
                b'{"ref":"cHJvY2Vzcy5lbnYuRkxBRw==","token":"0000000000000000"}',
                "sig-l2-rsc-action-env-ref-001",
            ),
            (
                "l2-graphql",
                8082,
                b"POST /graphql HTTP/1.1\r\nHost: x\r\n"
                b"Content-Type: application/json\r\n\r\n"
                b'{"query":"{ missionAudit { lastDeployment { notes } } }"}',
                "sig-l2-graphql-mission-audit-001",
            ),
        )
        for packet_id, (name, port, payload, rule_id) in enumerate(cases, start=1):
            with self.subTest(name=name):
                policy = HotPolicy(policy=self.compiled, clock=lambda: 0.0)
                packet = parse_ip(ipv4_tcp(payload, dst_port=port))
                decision = policy.decide(packet_id, packet, 0.0)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, rule_id)


if __name__ == "__main__":
    unittest.main()
