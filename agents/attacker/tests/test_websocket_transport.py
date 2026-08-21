import base64
import hashlib
import json
import unittest
from unittest.mock import patch

from aegis_attacker.websocket_transport import _GUID, mission_feed_request


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, _timeout):
        pass

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, size):
        if not self.incoming:
            return b""
        data = bytes(self.incoming[:size])
        del self.incoming[:size]
        return data


def server_text(document):
    payload = json.dumps(document, separators=(",", ":")).encode("utf-8")
    return bytes((0x81, len(payload))) + payload


def client_payload(frame):
    length = frame[1] & 0x7F
    offset = 2
    if length == 126:
        length = int.from_bytes(frame[offset:offset + 2], "big")
        offset += 2
    mask = frame[offset:offset + 4]
    payload = frame[offset + 4:offset + 4 + length]
    return bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload)), offset + 4 + length


class TestMissionFeedTransport(unittest.TestCase):
    def test_authenticates_then_requests_admin_fleet(self):
        key_bytes = b"K" * 16
        key = base64.b64encode(key_bytes)
        accept = base64.b64encode(hashlib.sha1(key + _GUID).digest())
        handshake = (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n"
        )
        incoming = handshake + server_text({"type": "auth_ok"}) + server_text({
            "type": "fleet", "relay_auth_token": "FLAG{ws-fixture}"
        })
        fake = FakeSocket(incoming)
        token = "0123456789abcdef0123456789abcdef"
        with patch(
            "aegis_attacker.websocket_transport.socket.create_connection",
            return_value=fake,
        ), patch(
            "aegis_attacker.websocket_transport.os.urandom",
            side_effect=[key_bytes, b"M" * 4, b"N" * 4],
        ):
            response = mission_feed_request(
                "team2.lig.internal", 8082, "/ws/mission-feed", token
            )

        self.assertEqual(response.status, 101)
        self.assertIn("FLAG{ws-fixture}", response.body)
        frames = bytes(fake.sent).split(b"\r\n\r\n", 1)[1]
        auth, consumed = client_payload(frames)
        command, _ = client_payload(frames[consumed:])
        self.assertEqual(json.loads(auth), {"type": "auth", "token": token})
        self.assertEqual(json.loads(command), {"type": "admin_fleet_request"})

    def test_response_body_is_bounded(self):
        key_bytes = b"K" * 16
        key = base64.b64encode(key_bytes)
        accept = base64.b64encode(hashlib.sha1(key + _GUID).digest())
        handshake = (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n"
        )
        fake = FakeSocket(handshake + server_text({"type": "auth_ok"}))
        with patch(
            "aegis_attacker.websocket_transport.socket.create_connection",
            return_value=fake,
        ), patch(
            "aegis_attacker.websocket_transport.os.urandom",
            side_effect=[key_bytes, b"M" * 4],
        ), patch(
            "aegis_attacker.websocket_transport.MAX_RESPONSE_BYTES",
            8,
        ):
            response = mission_feed_request(
                "team2.lig.internal", 8082, "/ws/mission-feed", "session"
            )

        self.assertEqual(response.status, 101)
        self.assertTrue(response.truncated)
        self.assertEqual(response.body, "")


if __name__ == "__main__":
    unittest.main()
