import unittest

from aegis_attacker.config import AttackerConfig
from aegis_attacker.egress import EgressError, EgressGateway, build_allowlists
from aegis_attacker.models import Capability
from aegis_attacker.observation import HttpResponse


class RecordingTransport:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        self.calls.append((method, url))
        return self.response

    def request_grpc(self, host, port, rpc, string_fields=None,
                     varint_fields=None, timeout=6.0):
        self.calls.append(("GRPC", host, port, rpc, string_fields, varint_fields))
        return self.response


CFG = AttackerConfig(
    targets=("team2.lig.internal",), ports=(8082, 8083, 9000),
    submit_url="http://10.99.50.4:4100/submit", submit_token="tok",
    llm_base_url="http://litellm.lig.internal:4000", llm_api_key="sk",
)


def make_gateway(resp=None):
    t = RecordingTransport(resp or HttpResponse(200, "ok"))
    return EgressGateway(t, build_allowlists(CFG)), t


class TestAllowlists(unittest.TestCase):
    def test_build(self):
        allow = build_allowlists(CFG)
        self.assertIn(("team2.lig.internal", 8082), allow[Capability.ATTACK_TARGET])
        self.assertIn(("team2.lig.internal", 8083), allow[Capability.ATTACK_TARGET])
        self.assertIn(("10.99.50.4", 4100), allow[Capability.SUBMIT])
        self.assertIn(("litellm.lig.internal", 4000), allow[Capability.LLM])


class TestEgressGateway(unittest.TestCase):
    def test_attack_target_in_scope(self):
        gw, t = make_gateway()
        gw.request(Capability.ATTACK_TARGET, "GET",
                   "http://team2.lig.internal:8082/fetch")
        self.assertEqual(len(t.calls), 1)

    def test_out_of_scope_rejected(self):
        gw, t = make_gateway()
        with self.assertRaises(EgressError):
            gw.request(Capability.ATTACK_TARGET, "GET", "http://evil.com:80/")
        self.assertEqual(len(t.calls), 0)  # 호출 전에 거부

    def test_capability_crossing_rejected(self):
        # SUBMIT capability로 공격 표적 host를 치려는 시도 거부
        gw, t = make_gateway()
        with self.assertRaises(EgressError):
            gw.request(Capability.SUBMIT, "POST",
                       "http://team2.lig.internal:8082/submit")
        self.assertEqual(len(t.calls), 0)

    def test_port_change_rejected(self):
        # 허용 포트(8082/8083) 밖은 거부
        gw, t = make_gateway()
        with self.assertRaises(EgressError):
            gw.request(Capability.ATTACK_TARGET, "GET",
                       "http://team2.lig.internal:9999/")

    def test_submit_and_llm_scoped(self):
        gw, t = make_gateway()
        gw.request(Capability.SUBMIT, "POST", "http://10.99.50.4:4100/submit")
        gw.request(Capability.LLM, "POST",
                   "http://litellm.lig.internal:4000/v1/chat/completions")
        self.assertEqual(len(t.calls), 2)

    def test_redirect_returned_as_observation(self):
        # 전송이 3xx를 반환하면 게이트웨이는 따라가지 않고 그대로 넘긴다
        gw, t = make_gateway(HttpResponse(302, "", {"Location": "http://x/"}))
        resp = gw.request(Capability.ATTACK_TARGET, "GET",
                          "http://team2.lig.internal:8082/")
        self.assertEqual(resp.status, 302)

    def test_attack_target_https_uses_target_specific_transport(self):
        class TargetTlsTransport:
            def __init__(self):
                self.normal_calls = 0
                self.target_calls = 0

            def request(self, *args, **kwargs):
                self.normal_calls += 1
                return HttpResponse(200, "normal")

            def request_target(self, *args, **kwargs):
                self.target_calls += 1
                return HttpResponse(200, "target")

        transport = TargetTlsTransport()
        gateway = EgressGateway(transport, build_allowlists(CFG))

        response = gateway.request(
            Capability.ATTACK_TARGET,
            "GET",
            "https://team2.lig.internal:8082/",
        )
        gateway.request(Capability.LLM, "POST", "http://litellm.lig.internal:4000/v1/chat/completions")

        self.assertEqual(response.body, "target")
        self.assertEqual(transport.target_calls, 1)
        self.assertEqual(transport.normal_calls, 1)

    def test_passive_tcp_banner_is_scoped_before_transport(self):
        class BannerTransport:
            def __init__(self):
                self.calls = []

            def read_passive_banner(self, host, port, timeout, max_bytes):
                self.calls.append((host, port, timeout, max_bytes))
                return HttpResponse(200, "banner")

        transport = BannerTransport()
        gateway = EgressGateway(transport, build_allowlists(CFG))

        response = gateway.read_passive_banner(
            Capability.ATTACK_TARGET, "team2.lig.internal", 8082
        )
        self.assertEqual(response.body, "banner")
        with self.assertRaises(EgressError):
            gateway.read_passive_banner(Capability.ATTACK_TARGET, "evil.invalid", 8082)
        self.assertEqual(len(transport.calls), 1)

    def test_grpc_attack_target_is_scoped_before_transport(self):
        gw, transport = make_gateway()
        response = gw.request_grpc(
            Capability.ATTACK_TARGET,
            "team2.lig.internal",
            9000,
            "/satdiag.v1.SatDiag/Health",
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(transport.calls[0][:4], (
            "GRPC", "team2.lig.internal", 9000, "/satdiag.v1.SatDiag/Health"
        ))
        with self.assertRaises(EgressError):
            gw.request_grpc(
                Capability.ATTACK_TARGET,
                "evil.invalid",
                9000,
                "/satdiag.v1.SatDiag/Health",
            )
        with self.assertRaises(EgressError):
            gw.request_grpc(
                Capability.LLM,
                "team2.lig.internal",
                9000,
                "/satdiag.v1.SatDiag/Health",
            )
        self.assertEqual(len(transport.calls), 1)

        with self.assertRaises(EgressError):
            gw.request_grpc(
                Capability.ATTACK_TARGET,
                "team2.lig.internal",
                9000,
                "/satdiag.v1.SatDiag/NotARealMethod",
            )

        gw.request_grpc(
            Capability.ATTACK_TARGET,
            "team2.lig.internal",
            9000,
            "/satdiag.v1.SatDiag/ExportDiagnosticBundle",
            {1: "telemetry.log;echo x${FLAG}x", 2: "capture", 3: "gzip"},
        )
        self.assertEqual(transport.calls[-1][3], "/satdiag.v1.SatDiag/ExportDiagnosticBundle")


if __name__ == "__main__":
    unittest.main()
