import subprocess
import sys
import unittest
from pathlib import Path


SRC_ROOT = Path(__file__).resolve().parents[1] / "src"


class TestStartupImports(unittest.TestCase):
    def test_main_import_defers_network_modules_until_async_advisory_call(self):
        """advisory가 미룬 모듈은 `urllib.request`와 `urllib.error` 둘 다다.

        하나만 지키면 나머지가 다시 startup 경로로 올라와도 회귀를 잡지 못한다.
        import 비용은 Broker 연결보다 먼저 지불되므로 그대로 fail-open 창이 된다.
        """
        code = (
            "import sys; import aegis_defender.main; "
            "leaked = [m for m in ('urllib.request', 'urllib.error') if m in sys.modules]; "
            "print(','.join(leaked)); "
            "raise SystemExit(1 if leaked else 0)"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            check=False,
            capture_output=True,
            cwd=SRC_ROOT,
            text=True,
        )

        self.assertEqual(
            result.returncode, 0,
            f"startup 경로로 올라온 모듈: {result.stdout.strip()}\n{result.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
