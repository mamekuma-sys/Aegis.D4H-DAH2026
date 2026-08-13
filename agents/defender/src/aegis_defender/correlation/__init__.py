"""비동기 상관분석 하위 패키지.

설계 §11 온라인 비동기 상관분석. 세 모듈로 나뉜다.

- `window.py`  시간 윈도우 — 도착 간격의 기계적 균일성과 bounded 최근 관측
- `causal.py`  `CausalMatcher` — 관측된 event와 key만 사용하는 chain match
- `risk.py`    `RiskModel` — 본선 fixture로 보정할 비동기 우선순위

**이 `__init__.py`는 의도적으로 아무것도 import 하지 않는다.** `state.py`가 세
모듈을 직접 import 하고 상관 worker가 `state.py`에 있기 때문에, 패키지 초기화가
`state.py`를 다시 끌어오면 순환 import가 된다. 편의 re-export를 추가하지 않는다.
"""
