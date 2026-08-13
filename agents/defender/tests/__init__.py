"""테스트 패키지. 표준 라이브러리 unittest만 사용한다.

`src/`를 import 경로에 추가해 외부 설치 없이 다음으로 실행할 수 있게 한다.

    cd agents/defender
    python -m unittest discover -s tests -t .
"""

import os
import sys

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
