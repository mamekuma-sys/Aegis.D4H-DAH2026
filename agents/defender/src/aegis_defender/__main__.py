"""`python -m aegis_defender` 진입점.

lifecycle 본체는 `main.py`에 있다(설계 §14 파일 구조). 이 파일은 모듈 실행 형태만
제공해 컨테이너 CMD를 짧게 유지한다 — 이미지 시작 시간이 Round 시간에 포함되므로
(운영세칙 제6조 3항) 시작 경로에 불필요한 단계를 두지 않는다.
"""

from __future__ import annotations

import sys

from .main import main

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
