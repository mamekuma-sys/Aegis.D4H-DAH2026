import unittest
from unittest.mock import patch

from aegis_attacker.grpc_transport import (
    CLIENT_PREFACE,
    READ_ONLY_RPCS,
    _frame,
    encode_protobuf,
    grpc_unary_request,
)


HEALTH = "/satdiag.v1.SatDiag/Health"
PROBE = "/satdiag.v1.SatDiag/ProbeEndpoint"


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, size):
        if not self.incoming:
            return b""
        chunk = bytes(self.incoming[:size])
        del self.incoming[:size]
        return chunk


class TestProtobufEncoding(unittest.TestCase):
    def test_observed_probe_fields_use_expected_wire_types(self):
        encoded = encode_protobuf({1: "telemetry", 2: "/flag"})
        self.assertEqual(encoded, b"\x0a\x09telemetry\x12\x05/flag")

    def test_observed_tail_max_lines_is_varint(self):
        encoded = encode_protobuf({1: "../../flag"}, {2: 200})
        self.assertIn(b"\x0a\x0a../../flag", encoded)
        self.assertTrue(encoded.endswith(b"\x10\xc8\x01"))


class TestGrpcUnaryRequest(unittest.TestCase):
    def test_h2c_unary_request_decodes_flag_message(self):
        response_message = encode_protobuf({4: "FLAG{grpc_fixture}"})
        envelope = b"\x00" + len(response_message).to_bytes(4, "big") + response_message
        incoming = b"".join((
            _frame(4, 0, 0),
            _frame(1, 0x04, 1),
            _frame(0, 0x01, 1, envelope),
        ))
        fake = FakeSocket(incoming)

        with patch(
            "aegis_attacker.grpc_transport.socket.create_connection",
            return_value=fake,
        ):
            response = grpc_unary_request(
                "team2.lig.internal",
                9000,
                PROBE,
                {1: "telemetry", 2: "/flag"},
                {},
            )

        self.assertEqual(response.status, 200)
        self.assertIn("FLAG{grpc_fixture}", response.body)
        self.assertTrue(fake.sent.startswith(CLIENT_PREFACE))
        self.assertIn(PROBE.encode(), fake.sent)
        self.assertIn(b"application/grpc", fake.sent)
        self.assertIn(b"telemetry", fake.sent)
        self.assertIn(_frame(4, 0x01, 0), fake.sent)  # server SETTINGS ACK

    def test_unobserved_rpc_is_rejected_before_connect(self):
        with patch(
            "aegis_attacker.grpc_transport.socket.create_connection"
        ) as connect:
            response = grpc_unary_request(
                "team2.lig.internal", 9000,
                "/satdiag.v1.SatDiag/ExportDiagnosticBundle",
            )
        self.assertEqual(response.status, 0)
        connect.assert_not_called()

    def test_catalog_contains_only_read_only_methods(self):
        self.assertEqual(
            READ_ONLY_RPCS,
            frozenset({HEALTH, PROBE, "/satdiag.v1.SatDiag/TailDiagnosticLog"}),
        )


if __name__ == "__main__":
    unittest.main()
