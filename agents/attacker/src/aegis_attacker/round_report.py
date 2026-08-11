"""비밀 없는 Round 결과 요약.

설계 §9.6·§7.6. 라운드 종료 시 토큰·키·flag 원문·상대 팀 비밀을 제거한 개발 산출물만
요약한다. 요약은 다음 Round 개선 근거로 팀이 검토한다. flag는 해시로만 집계한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import RoundBudget, SubmitState


@dataclass
class RoundReport:
    """라운드 관측·제출·예산 집계(비밀 없음)."""

    endpoints_observed: int = 0
    requests_made: int = 0
    submit_states: dict = field(default_factory=dict)  # state.value -> count
    accepted_flag_hashes: set = field(default_factory=set)  # 해시만
    budget: RoundBudget = field(default_factory=RoundBudget)

    def record_observation(self) -> None:
        self.endpoints_observed += 1

    def record_request(self) -> None:
        self.requests_made += 1

    def record_submit(self, flag_hash: str, state: SubmitState) -> None:
        key = state.value
        self.submit_states[key] = self.submit_states.get(key, 0) + 1
        if state == SubmitState.ACCEPTED:
            self.accepted_flag_hashes.add(flag_hash)

    def accepted_count(self) -> int:
        return len(self.accepted_flag_hashes)

    def summary(self) -> dict:
        """비밀 없는 요약 dict. flag는 개수·해시 접두만."""
        return {
            "endpoints_observed": self.endpoints_observed,
            "requests_made": self.requests_made,
            "submit_states": dict(self.submit_states),
            "accepted_count": self.accepted_count(),
            "accepted_flag_hash_prefixes": sorted(h[:12] for h in self.accepted_flag_hashes),
            "llm_calls": self.budget.llm_calls,
            "llm_tokens": self.budget.llm_tokens,
        }
