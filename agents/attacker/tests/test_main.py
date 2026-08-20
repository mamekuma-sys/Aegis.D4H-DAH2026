import signal
import unittest
from unittest.mock import patch

from aegis_attacker.__main__ import install_signal_handlers


class RecordingAudit:
    def __init__(self):
        self.events = []

    def log(self, event, **fields):
        self.events.append((event, fields))


class RuntimeStub:
    def __init__(self):
        self.audit = RecordingAudit()
        self.stop_requested = False

    def request_stop(self):
        self.stop_requested = True


class TestSignalHandling(unittest.TestCase):
    def test_sigterm_logs_and_interrupts_the_round(self):
        runtime = RuntimeStub()
        handlers = {}

        with patch(
            "aegis_attacker.__main__.signal.signal",
            side_effect=lambda received, handler: handlers.__setitem__(received, handler),
        ):
            install_signal_handlers(runtime)

        self.assertIn(signal.SIGTERM, handlers)
        with self.assertRaises(KeyboardInterrupt):
            handlers[signal.SIGTERM](signal.SIGTERM, None)
        self.assertEqual(runtime.audit.events, [("signal", {"signum": signal.SIGTERM})])
        self.assertTrue(runtime.stop_requested)


if __name__ == "__main__":
    unittest.main()
