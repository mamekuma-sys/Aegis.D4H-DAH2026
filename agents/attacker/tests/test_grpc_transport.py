import unittest
from unittest.mock import patch

from aegis_attacker.grpc_transport import (
    ALLOWED_GRPC_RPCS_BY_PORT,
    CLIENT_PREFACE,
    READ_ONLY_RPCS,
    _frame,
    encode_protobuf,
    grpc_unary_request,
)


HEALTH = "/satdiag.v1.SatDiag/Health"
PROBE = "/satdiag.v1.SatDiag/ProbeEndpoint"
EXPORT = "/satdiag.v1.SatDiag/ExportDiagnosticBundle"
TAIL = "/satdiag.v1.SatDiag/TailDiagnosticLog"
G2DDS_CATALOG = "/g2dds.v1.Layer4Service/GetCatalog"
G2DDS_EXCHANGE = "/g2dds.v1.Layer4Service/Exchange"


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
                "/satdiag.v1.SatDiag/NotARealMethod",
            )
        self.assertEqual(response.status, 0)
        connect.assert_not_called()

    def test_rpc_is_bound_to_observed_port(self):
        with patch(
            "aegis_attacker.grpc_transport.socket.create_connection"
        ) as connect:
            self.assertEqual(
                grpc_unary_request("team2.lig.internal", 8410, HEALTH).status, 0
            )
            self.assertEqual(
                grpc_unary_request("team2.lig.internal", 9000, G2DDS_CATALOG).status, 0
            )
        connect.assert_not_called()

    def test_fragmented_huffman_delivery_hides_path_and_splits_envelope(self):
        incoming = b"".join((
            _frame(4, 0, 0),
            _frame(1, 0x04, 1),
            _frame(0, 0x01, 1, b"\x00\x00\x00\x00\x00"),
        ))
        fake = FakeSocket(incoming)
        with patch(
            "aegis_attacker.grpc_transport.socket.create_connection",
            return_value=fake,
        ):
            response = grpc_unary_request(
                "team2.lig.internal", 9000, TAIL,
                {1: "/flag"}, {2: 1}, delivery="fragmented_huffman",
            )

        self.assertEqual(response.status, 200)
        self.assertNotIn(TAIL.encode("ascii"), fake.sent)
        offset = len(CLIENT_PREFACE)
        data_lengths = []
        while offset + 9 <= len(fake.sent):
            length = int.from_bytes(fake.sent[offset:offset + 3], "big")
            frame_type = fake.sent[offset + 3]
            if frame_type == 0:
                data_lengths.append(length)
            offset += 9 + length
        message = encode_protobuf({1: "/flag"}, {2: 1})
        self.assertEqual(data_lengths, [1] * (5 + len(message)))

    def test_catalog_contains_only_observed_port_rpc_pairs(self):
        self.assertEqual(
            READ_ONLY_RPCS,
            frozenset({HEALTH, PROBE, TAIL, EXPORT, G2DDS_CATALOG, G2DDS_EXCHANGE}),
        )
        self.assertEqual(ALLOWED_GRPC_RPCS_BY_PORT[9000], {HEALTH, PROBE, TAIL, EXPORT})
        self.assertEqual(ALLOWED_GRPC_RPCS_BY_PORT[8410], {G2DDS_CATALOG, G2DDS_EXCHANGE})
        self.assertEqual(ALLOWED_GRPC_RPCS_BY_PORT[8420], {G2DDS_CATALOG, G2DDS_EXCHANGE})


if __name__ == "__main__":
    unittest.main()
