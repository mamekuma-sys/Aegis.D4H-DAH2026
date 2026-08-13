"""공격 에이전트 진입점.

`python -m aegis_attacker` 로 실행한다. 환경변수(운영세칙 제16조)로만 설정을 받고,
필수 값 형식 오류는 로그 후 종료, 값 누락은 inert(fail-open)로 처리한다(§9.13).
"""

from __future__ import annotations

import os
import sys

from .audit import AuditLogger
from .config import ConfigError, load_config
from .runtime import AttackerRuntime


def main() -> int:
    try:
        config = load_config(os.environ)
    except ConfigError as exc:
        AuditLogger().log("config-error", error=str(exc))
        return 1
    AttackerRuntime(config).run_forever()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
