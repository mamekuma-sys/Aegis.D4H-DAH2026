"""Real Linux AF_UNIX/SOCK_SEQPACKET transport smoke test.

macOS commonly rejects this socket type, so the test skips there. CI and the finals
container are Linux and therefore exercise the same message-boundary transport used
by the Broker contract instead of the cross-platform fake transport.
"""

import io
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from aegis_defender.config import RuntimeConfig
from aegis_defender.logging import AuditLogger
from aegis_defender.main import DefenderRuntime
from aegis_defender.metrics import L_VERDICT_SEND_E2E, Metrics
from aegis_defender.protocol import (
    HEARTBEAT_FRAME,
    MSG_VERDICT,
    VERDICT_ACCEPT,
    decode_verdict,
)
from aegis_defender.session import (
    OutboundQueue,
    SendOutcome,
    SocketTransport,
    SocketWriter,
    VerdictSender,
)

from .fakes import http_request, ipv4_tcp, packet_frame


POLICY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policy"))


class TestLinuxSeqpacketTransport(unittest.TestCase):
    def _require_seqpacket(self):
        try:
            first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        except (AttributeError, OSError) as exc:
            self.skipTest(f"AF_UNIX/SOCK_SEQPACKET unavailable: {type(exc).__name__}")
        first.close()
        second.close()

    def test_real_socket_send_completion_is_inside_broker_deadline(self):
        try:
            writer_socket, broker_socket = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET
            )
        except (AttributeError, OSError) as exc:
            self.skipTest(f"AF_UNIX/SOCK_SEQPACKET unavailable: {type(exc).__name__}")

        try:
            metrics = Metrics()
            queue = OutboundQueue()
            session_id = queue.new_session()
            transport = SocketTransport(writer_socket)
            writer = SocketWriter(queue, metrics=metrics)
            writer.attach(transport, session_id)
            sender = VerdictSender(queue, metrics=metrics)

            received_at = time.monotonic()
            self.assertTrue(sender.send(42, VERDICT_ACCEPT, received_at))
            result = writer.send_once(0.0)
            self.assertIsNotNone(result)
            self.assertIs(result.outcome, SendOutcome.SENT)
            self.assertEqual(decode_verdict(broker_socket.recv(64)), (42, VERDICT_ACCEPT))

            summary = metrics.latency_summary(L_VERDICT_SEND_E2E)
            self.assertEqual(summary["count"], 1.0)
            self.assertGreaterEqual(summary["max_us"], 0.0)
            self.assertLess(summary["max_us"], 300_000.0)
        finally:
            writer_socket.close()
            broker_socket.close()

    def test_full_runtime_broker_contract_over_real_linux_socket(self):
        self._require_seqpacket()
        with tempfile.TemporaryDirectory() as temp_dir:
            socket_path = os.path.join(temp_dir, "agent.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            listener.bind(socket_path)
            listener.listen(1)
            listener.settimeout(3.0)
            stream = io.StringIO()
            with mock.patch("aegis_defender.rules.time.time", return_value=1786764000.0):
                runtime = DefenderRuntime(
                    RuntimeConfig(agent_socket=socket_path, policy_dir=POLICY_DIR),
                    audit=AuditLogger(stream=stream),
                )
            runtime_thread = threading.Thread(target=runtime.run, daemon=True)
            runtime_thread.start()
            connection = None
            try:
                connection, _ = listener.accept()
                connection.settimeout(3.0)
                connection.send(packet_frame(42, ipv4_tcp(http_request("/health"))))
                verdict = None
                deadline = time.monotonic() + 3.0
                while time.monotonic() < deadline:
                    frame = connection.recv(64)
                    if frame and frame[0] == MSG_VERDICT:
                        verdict = decode_verdict(frame)
                        break
                self.assertEqual(verdict, (42, VERDICT_ACCEPT))
                self.assertEqual(connection.recv(64), HEARTBEAT_FRAME)
                self.assertEqual(runtime.policy_report.source, "active")
                self.assertEqual(runtime.policy_report.drop_capable_rules, 28)
                summary = runtime.metrics.latency_summary(L_VERDICT_SEND_E2E)
                self.assertEqual(summary["count"], 1.0)
                self.assertLess(summary["max_us"], 300_000.0)
            finally:
                runtime.stop_event.set()
                runtime.session.stop()
                if connection is not None:
                    connection.close()
                listener.close()
                runtime_thread.join(timeout=3.0)
                self.assertFalse(runtime_thread.is_alive())


if __name__ == "__main__":
    unittest.main()
