import subprocess
import sys
import unittest


class TestStartupImports(unittest.TestCase):
    def test_main_import_defers_urllib_request_until_async_advisory_call(self):
        code = (
            "import sys; import aegis_defender.main; "
            "raise SystemExit(1 if 'urllib.request' in sys.modules else 0)"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
