"""FinalsPhase 우선순위 정책 — 누적 레이어 공정 예산 배분.

설계 §7.3·§9.9. 새 레이어가 열려도 이전 레이어가 요청 예산에서 굶지 않도록 표적별 예산을
공정 배분하고 라운드로빈으로 순회한다. 성공 가능성이 확인된 표적은 제한 안에서 우선순위를
높인다. 공식 계약에 없는 PHASE/LAYER/ROUND 환경변수를 요구하지 않는다 — 실제 관측되는
표적 집합(엔드포인트)을 입력으로 받는다.
"""

from __future__ import annotations

from .models import Endpoint

# 본선 구조(운영세칙 제4·5조, 당일안내 §1): 4 FinalsPhase, Round 수 2·4·4·4, 총 14.
# 레이어는 Phase N에서 Layer 1~N 누적 개방. 공식 계약에 없는 PHASE/LAYER/ROUND env는
# 요구하지 않으며, 이 표는 참고·스케줄 힌트일 뿐 런타임 필수 입력이 아니다(§7.3·§9.9).
FINALS_PHASE_ROUNDS = {1: 2, 2: 4, 3: 4, 4: 4}
TOTAL_ROUNDS = 14


def rounds_in_phase(phase: int) -> int:
    if phase not in FINALS_PHASE_ROUNDS:
        raise ValueError(f"FinalsPhase 는 1~4: {phase}")
    return FINALS_PHASE_ROUNDS[phase]


def layers_open(phase: int) -> list:
    """FinalsPhase N에서 누적 개방되는 레이어 1~N."""
    if phase not in FINALS_PHASE_ROUNDS:
        raise ValueError(f"FinalsPhase 는 1~4: {phase}")
    return list(range(1, phase + 1))


def total_rounds() -> int:
    return sum(FINALS_PHASE_ROUNDS.values())


# 본선 레이어 진입 포트 (대회 대시보드 기준).
# L1 starlink-gw: 8080 HTTP · 9000 gRPC SatDiag
# L2 mission-c2: 8082
# L3 uav-node: 1883 MQTT · 8554 RTSP · 9090
# L4 ugv-node: 8410 · 8420
_LAYER_PORTS = {
    8080: 1,
    9000: 1,
    8082: 2,
    1883: 3,
    8554: 3,
    9090: 3,
    8410: 4,
    8420: 4,
}


def layer_of_port(port: int) -> int:
    return _LAYER_PORTS.get(port, 0)  # 미상


def cumulative_endpoint_order(endpoints) -> list:
    """누적 개방 레이어를 공정하게 섞되 새 L4를 첫 wave에 포함한다.

    알려진 본선 포트는 host별로 ``L4→L1→L2→L3`` 순환한다. Phase 4 UGV를 늦게
    시작하지 않으면서도 이전 레이어가 굶지 않게 한 슬롯씩 배치한다. 포트-레이어 관계가
    관측되지 않은 endpoint는 입력 순서를 보존하며, 전부 미상인 경우 원본 순서 그대로다.
    """
    original = list(endpoints)
    by_layer = {layer: [] for layer in range(1, 5)}
    unknown = []
    for endpoint in original:
        layer = layer_of_port(endpoint.port)
        if layer:
            by_layer[layer].append(endpoint)
        else:
            unknown.append(endpoint)
    if not any(by_layer.values()):
        return original

    ordered = []
    width = max([len(items) for items in by_layer.values()] + [len(unknown)])
    for index in range(width):
        for layer in (4, 1, 2, 3):
            if index < len(by_layer[layer]):
                ordered.append(by_layer[layer][index])
        if index < len(unknown):
            ordered.append(unknown[index])
    return ordered


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
