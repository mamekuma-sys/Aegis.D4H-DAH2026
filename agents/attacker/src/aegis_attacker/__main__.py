"""공격 에이전트 진입점.

`python -m aegis_attacker` 로 실행한다. 환경변수(운영세칙 제16조)로만 설정을 받고,
필수 값 형식 오류는 로그 후 종료, 값 누락은 inert(fail-open)로 처리한다(§9.13).
"""

from __future__ import annotations

import os
import signal
import sys

from .audit import AuditLogger
from .config import ConfigError, load_config
from .runtime import AttackerRuntime


def install_signal_handlers(runtime: AttackerRuntime) -> None:
    """컨테이너 종료 신호를 정상적인 라운드 종료 경로로 전환한다."""

    def _handle_signal(signum: int, _frame: object) -> None:
        runtime.audit.log("signal", signum=signum)
        raise KeyboardInterrupt

    for received_signal in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(received_signal, _handle_signal)
        except (OSError, ValueError):
            # 메인 스레드가 아니거나 플랫폼이 신호를 지원하지 않는 테스트 환경.
            continue


def main() -> int:
    try:
        config = load_config(os.environ)
    except ConfigError as exc:
        AuditLogger().log("config-error", error=str(exc))
        return 1
    runtime = AttackerRuntime(config)
    install_signal_handlers(runtime)
    runtime.run_forever()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
