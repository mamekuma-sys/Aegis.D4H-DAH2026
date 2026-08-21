import socket
import unittest
from unittest.mock import patch

from aegis_attacker.protocol_transport import mqtt_read_request, rtsp_read_request


class ChunkSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = []
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.sent.append(bytes(data))

    def recv(self, _size):
        if not self.chunks:
            raise socket.timeout()
        return self.chunks.pop(0)


class TestMqttTransport(unittest.TestCase):
    def test_connect_and_read_subscription_capture_retained_flag(self):
        fake = ChunkSocket([
            b"\x20\x02\x00\x00",
            b"\x90\x03\x00\x01\x00",
            b"\x30\x1fuav/telemetry FLAG{mqtt-retained}",
        ])
        with patch("aegis_attacker.protocol_transport.socket.create_connection", return_value=fake):
            response = mqtt_read_request("team2", 1883, ("#", "$SYS/#"))

        self.assertEqual(response.status, 200)
        self.assertIn("FLAG{mqtt-retained}", response.body)
        self.assertEqual(fake.sent[0][0] >> 4, 1)  # CONNECT
        self.assertEqual(fake.sent[1][0] >> 4, 8)  # SUBSCRIBE
        self.assertIn(b"$SYS/#", fake.sent[1])

    def test_wrong_port_fails_without_socket(self):
        with patch("aegis_attacker.protocol_transport.socket.create_connection") as connect:
            response = mqtt_read_request("team2", 1884, ("#",))
        self.assertEqual(response.status, 0)
        connect.assert_not_called()


class TestRtspTransport(unittest.TestCase):
    def test_describe_is_read_only_and_returns_sdp(self):
        fake = ChunkSocket([
            b"RTSP/1.0 200 OK\r\nContent-Type: application/sdp\r\n\r\n"
            b"a=x-flag:FLAG{rtsp-sdp}",
        ])
        with patch("aegis_attacker.protocol_transport.socket.create_connection", return_value=fake):
            response = rtsp_read_request("team2", 8554, "DESCRIBE", "/live")

        self.assertEqual(response.status, 200)
        self.assertIn("FLAG{rtsp-sdp}", response.body)
        self.assertTrue(fake.sent[0].startswith(b"DESCRIBE rtsp://team2:8554/live RTSP/1.0"))
        self.assertNotIn(b"PLAY ", fake.sent[0])

    def test_mutating_method_is_rejected_before_socket(self):
        with patch("aegis_attacker.protocol_transport.socket.create_connection") as connect:
            response = rtsp_read_request("team2", 8554, "PLAY", "/live")
        self.assertEqual(response.status, 0)
        connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
