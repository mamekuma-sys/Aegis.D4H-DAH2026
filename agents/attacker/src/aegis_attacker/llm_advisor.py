"""LLM 조언 경계와 라운드 예산.

설계 §9.12. LLM은 관측 요약·exploit 우선순위 조언에만 쓴다. 출력은 도구를 직접 실행하지
못하고 planner→범위·예산 검사를 다시 통과한다. 프롬프트·로그에 SUBMIT_TOKEN·LLM_API_KEY·
flag 원문을 넣지 않는다(Redactor로 강제). 라운드별 호출·토큰 예산을 기록하고 초과 시 조언을
중단해 결정론 경로로 넘어간다. 서버 호스팅 tools는 프록시가 차단한다.
"""

from __future__ import annotations

import json

from .audit import Redactor
from .config import (
    DEFAULT_LLM_FALLBACK_MODEL,
    DEFAULT_LLM_FALLBACK_MODELS,
    DEFAULT_LLM_MODEL,
)
from .models import Capability, RoundBudget
from .planner import parse_exploit

MAX_LLM_CALLS_PER_ROUND = 360  # 비싼 pro·전 표적·다유형. LLM 스킵 없이 flag 우선.
LLM_TIMEOUT = 45.0
LLM_MAX_COMPLETION_TOKENS = 1600
LLM_REASONING_EFFORT = "high"
_RETRYABLE_LLM_STATUSES = frozenset({0, 408, 409, 425, 429, 500, 502, 503, 504})
# 공격 대상이 반환한 최대 1MiB 응답을 그대로 prompt로 보내지 않는다. 토큰 수는
# tokenizer 없이 정확히 계산할 수 없으므로 UTF-8 byte를 보수적인 상한으로 사용한다.
# 시작의 service 설명과 끝의 최신 error를 함께 남겨 관측 증거의 양쪽 경계를 보존한다.
MAX_LLM_USER_CONTENT_BYTES = 8 * 1024
_TRUNCATION_MARKER = "\n[OBSERVATION_TRUNCATED]\n"


def _bounded_user_content(text: str) -> str:
    raw = (text or "").encode("utf-8")
    if len(raw) <= MAX_LLM_USER_CONTENT_BYTES:
        return text or ""

    marker = _TRUNCATION_MARKER.encode("utf-8")
    remaining = MAX_LLM_USER_CONTENT_BYTES - len(marker)
    head_size = (remaining + 1) // 2
    tail_size = remaining - head_size
    head = raw[:head_size].decode("utf-8", "ignore")
    tail = raw[-tail_size:].decode("utf-8", "ignore") if tail_size else ""
    return head + _TRUNCATION_MARKER + tail

# 공식 skeleton guide는 제공 모델의 원래 API 유형과 무관하게 LiteLLM이 모두
# `/v1/chat/completions` 요청을 투명 변환한다고 명시한다. 따라서 공지된 21개 ID만
# 허용하고, 그 밖의 임의 모델은 fail-safe로 생략한다.
SUPPORTED_LLM_MODELS = frozenset({
    "gpt-4o-mini",
    "gpt-4.1-mini",
    "gpt-4.1",
    "gpt-4o",
    "gpt-5",
    "gpt-5.2",
    "gpt-5-mini",
    "gpt-5.4",
    "gpt-5.6-luna",
    "gpt-5.6-terra",
    "gpt-5.6-sol",
    "o3",
    "o4-mini",
    "gpt-5-pro",
    "gpt-5.4-pro",
    "gpt-5-codex",
    "gpt-5.1-codex",
    "gpt-5.1-codex-mini",
    "gpt-5.1-codex-max",
    "gpt-5.2-codex",
    "gpt-5.3-codex",
})

SYSTEM_PROMPT = (
    "You are an offensive web-security agent in an authorized finals CTF. Every opposing team host hides "
    "FLAG{...}. Use the banner and every feedback status/header/body fragment. Prefer the highest-probability "
    "path for THIS port, then rotate classes until a flag appears.\n"
    "Finals layer map (entry ports):\n"
    "- L1 starlink-gw TCP 8080 HTTP + 9000 gRPC SatDiag (9000 is NOT plain HTTP).\n"
    "- L2 mission-c2 TCP 8082 — GraphQL often leaks FLAG in missionAudit.lastDeployment.notes.\n"
    "- L3 uav-node TCP 9090 HTTP (also 1883 MQTT / 8554 RTSP elsewhere).\n"
    "- L4 ugv-node TCP 8410/8420 — probe any advertised telemetry/control GET routes only.\n"
    "Must-try classes (rotate if blocked):\n"
    "- GraphQL OTHER: POST /graphql Content-Type application/json with bodies like "
    '{"query":"{ missionAudit { lastDeployment { notes } } }"} or { missionAudit } or systemConfig. '
    "Also try introspection __schema if notes are empty.\n"
    "- LFI: /config?file=, /read?path=, /download?file= → /flag, ../flag, /proc/self/environ, flag.txt.\n"
    "- SSRF: /fetch|/proxy url/uri/host → http://helper-box:8080/secret, helper-box.:8080/secret, "
    "http://127.0.0.1:<same-port>/secret|/registry|/flag|/admin, decimal/hex IP forms.\n"
    "- AUTH: /admin with Cookie session= urlsafe-base64 JSON {\"role\":\"admin\"} (padding variants).\n"
    "- SQLI: /product?id= UNION SELECT from app_meta / sqlite_master; match column count from errors.\n"
    "- Direct dumps: GET /flag /secret /admin /debug /rc/status /teleop/status /api/flag /graphql.\n"
    "If a payload times out while GET / worked, mutate encoding (double-URL, case, UN/**/ION) — do not repeat.\n"
    'Reply ONLY JSON (no fences): "vuln" LFI|SSRF|AUTH|SQLI|OTHER, "method" GET|POST, '
    '"path", "headers" object, "body" string, "reason" short. Path only — no host.'
)


class LLMAdvisor:
    """LiteLLM 프록시에 `LLM` egress로 조언을 요청한다. 실행 권한 없음.

    LLM 키는 Round 비밀 저장소 handle로만 참조하고, 프롬프트는 flag·세션·키·토큰 원문을
    Redactor로 제거한 뒤 전달한다(§9.12).
    """

    def __init__(self, egress, config, budget: RoundBudget, secret_store,
                 llm_key_handle, max_calls: int = MAX_LLM_CALLS_PER_ROUND):
        self._egress = egress
        self._config = config
        self._budget = budget
        self._store = secret_store
        self._key_handle = llm_key_handle
        self._max_calls = max_calls

    def advise_exploit(self, banner: str, feedback: str, hints, model: str = None):
        if self._key_handle is None:
            return None
        model_id = model or self._config.llm_model
        if model_id not in SUPPORTED_LLM_MODELS:
            return None

        # 현재 저장된 모든 비밀 원문을 프롬프트에서 제거(플러스 FLAG 정규식).
        redactor = Redactor(self._store.secrets_snapshot())
        hint_line = "Priority hints: " + ", ".join(h.value for h in hints) if hints else ""
        observed = "\n".join(
            part for part in (
                "Service observations:\n" + (banner or ""),
                "Latest attempt feedback:\n" + feedback if feedback else "",
            ) if part
        )
        user_content = _bounded_user_content(
            redactor.scrub("\n".join(x for x in (hint_line, observed) if x))
        )

        result, retryable = self._request_model(model_id, user_content)
        if result is not None:
            return result
        # 강제 primary(pro)가 재시도 가능 실패일 때만 sol→terra로 이어간다.
        # 테스트·명시 model 호출은 fallback 없이 그 모델 결과만 본다.
        if model_id != DEFAULT_LLM_MODEL or not retryable:
            return None
        for fallback in DEFAULT_LLM_FALLBACK_MODELS:
            if fallback not in SUPPORTED_LLM_MODELS:
                continue
            result, retryable = self._request_model(fallback, user_content)
            if result is not None:
                return result
            if not retryable:
                return None
        return None

    def _request_model(self, model_id: str, user_content: str):
        """한 upstream 호출을 예산에 예약하고 `(계획, 재시도 가능)`을 반환한다."""
        if not self._budget.try_reserve_llm(self._max_calls):
            return None, False

        is_gpt56 = model_id.startswith("gpt-5.6-")
        payload_obj = {
            "model": model_id,
            "max_completion_tokens": LLM_MAX_COMPLETION_TOKENS,
            "messages": [
                {"role": "developer" if is_gpt56 else "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
        }
        if is_gpt56:
            payload_obj["reasoning_effort"] = LLM_REASONING_EFFORT
        else:
            payload_obj["temperature"] = 0

        payload = json.dumps(payload_obj)
        api_key = self._store.resolve(self._key_handle)  # 원문은 여기서만
        try:
            resp = self._egress.request(
                Capability.LLM, "POST",
                self._config.llm_base_url + "/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                body=payload, timeout=LLM_TIMEOUT,
            )
        except Exception:
            # 전송 계층 예외도 timeout/status=0과 같은 fail-open 결과로 수렴한다.
            return None, True
        # 호출 수는 try_reserve_llm에서 이미 원자적으로 예약됨. 여기선 토큰만 가산.
        if resp.status != 200:
            return None, resp.status in _RETRYABLE_LLM_STATUSES
        try:
            obj = json.loads(resp.body)
            self._budget.add_llm(0, int(obj.get("usage", {}).get("total_tokens", 0) or 0))
            choice = obj["choices"][0]
            if choice.get("finish_reason") == "length":
                return None, True
            content = choice["message"]["content"]
        except Exception:
            return None, True
        try:
            plan = parse_exploit(content)
        except Exception:
            return None, True
        return plan, plan is None
