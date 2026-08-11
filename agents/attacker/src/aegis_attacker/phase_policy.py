"""FinalsPhase 우선순위 정책 — 누적 레이어 공정 예산 배분.

설계 §7.3·§9.9. 새 레이어가 열려도 이전 레이어가 요청 예산에서 굶지 않도록 표적별 예산을
공정 배분하고 라운드로빈으로 순회한다. 성공 가능성이 확인된 표적은 제한 안에서 우선순위를
높인다. 공식 계약에 없는 PHASE/LAYER/ROUND 환경변수를 요구하지 않는다 — 실제 관측되는
표적 집합(엔드포인트)을 입력으로 받는다.
"""

from __future__ import annotations

from .models import Endpoint

# 데모 포트 → 레이어 추정(8082→1). 본선 포트는 매핑 불가할 수 있으므로 참고용.
def layer_of_port(port: int) -> int:
    if 8082 <= port <= 8099:
        return port - 8081
    return 0  # 미상


def allocate_budget(endpoints, total_budget: int) -> dict:
    """전체 예산을 표적 수로 균등 배분(각 최소 1). 누적 레이어 공정 배분."""
    eps = list(endpoints)
    if not eps:
        return {}
    per = max(1, total_budget // len(eps))
    return {e: per for e in eps}


class FairScheduler:
    """표적별 예산을 지키며 라운드로빈으로 다음 표적을 고른다."""

    def __init__(self, endpoints, per_target_budget: int, boost_extra: int = 3):
        self._order = list(endpoints)
        self._budget = {e: per_target_budget for e in self._order}
        self._idx = 0
        self._boost_extra = boost_extra

    def remaining(self, endpoint: Endpoint) -> int:
        return self._budget.get(endpoint, 0)

    def next(self):
        """예산이 남은 다음 표적을 라운드로빈으로 반환. 모두 소진이면 None."""
        n = len(self._order)
        for _ in range(n):
            e = self._order[self._idx % n]
            self._idx += 1
            if self._budget.get(e, 0) > 0:
                return e
        return None

    def charge(self, endpoint: Endpoint, n: int = 1) -> None:
        if endpoint in self._budget:
            self._budget[endpoint] = max(0, self._budget[endpoint] - n)

    def boost(self, endpoint: Endpoint) -> None:
        """성공 가능성이 확인된 표적에 제한 안에서 예산을 더 준다."""
        if endpoint in self._budget:
            self._budget[endpoint] += self._boost_extra

    def all_exhausted(self) -> bool:
        return all(v <= 0 for v in self._budget.values())

    def add_endpoints(self, endpoints, per_target_budget: int) -> None:
        """새 레이어 개방 시 표적을 추가한다. 기존 표적 예산은 유지."""
        for e in endpoints:
            if e not in self._budget:
                self._order.append(e)
                self._budget[e] = per_target_budget
