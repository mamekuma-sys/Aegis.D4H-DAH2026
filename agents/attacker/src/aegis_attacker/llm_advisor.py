"""LLM 조언 경계와 라운드 예산.

설계 §9.12. LLM은 관측 요약·exploit 우선순위 조언에만 쓴다. 출력은 도구를 직접 실행하지
못하고 planner→범위·예산 검사를 다시 통과한다. 프롬프트·로그에 SUBMIT_TOKEN·LLM_API_KEY·
flag 원문을 넣지 않는다(Redactor로 강제). 라운드별 호출·토큰 예산을 기록하고 초과 시 조언을
중단해 결정론 경로로 넘어간다. 서버 호스팅 tools는 프록시가 차단한다.
"""

from __future__ import annotations

import json

from .audit import Redactor
from .models import Capability, RoundBudget
from .planner import parse_exploit

MAX_LLM_CALLS_PER_ROUND = 160  # 고가용·다턴 공략용. 대표 solver + 재시도 여유.
LLM_TIMEOUT = 20.0
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

# 맵게: 저가/중간 없이 최상단 고가용만. 전 턴 gpt-5.4-pro.
ESCALATION_MODELS = ("gpt-5.4-pro",)


def escalated_model(base: str, level: int) -> str:
    """항상 고가용 최상단. base·level과 무관하게 gpt-5.4-pro."""
    return ESCALATION_MODELS[-1]

SYSTEM_PROMPT = (
    "You are an offensive web-security agent in an authorized CTF attack-defense match. Each target is an "
    "unknown web service that hides a flag of the form FLAG{...} behind a web vulnerability. You receive the "
    "service's HTTP banner (GET /) and, after each attempt, the previous response (status, notable headers, "
    "body). Exploit every leaked detail: banner text, example URLs, error messages, response headers/cookies, "
    "and SQL/stack errors all disclose how to craft the next request.\n"
    "Playbook — pick the one that fits the banner/hints, then refine using feedback:\n"
    "- LFI / path traversal (file/view/read/download/path param): read a flag file directly. Try /flag, "
    "/flags/, ./flag, ../flag, flag.txt and any filename an error reveals.\n"
    "- SSRF (url/fetch/proxy/callback param): the banner may disclose an internal host:port or a loopback-only "
    "endpoint (e.g. /registry) reachable through the SSRF itself (fetch http://127.0.0.1:<same port>/<endpoint>). "
    "Such an index may return an internal URL, sometimes base64 — decode it, then SSRF that URL for the flag.\n"
    "- Broken auth / privilege escalation (admin/account/private area): the app may trust a client-supplied "
    "header or cookie. If a plain header, resend it high (admin/true/1). If the session cookie is base64/JWT, "
    "decode it, raise the privilege field (role -> admin), re-encode the same way, resend.\n"
    "- SQL injection (id/search/product param concatenated into SQL): use UNION SELECT. Read the SQL error to "
    "learn engine and column count. Enumerate schema (sqlite: UNION SELECT sql FROM sqlite_master), find the "
    "column holding the secret/flag, then UNION SELECT it. Match column count.\n"
    "Filter/WAF evasion — if a request that should reach the app gets NO response (dropped/timeout) while GET / "
    "worked, an inline content filter is DROPPING it by payload signature. Do NOT resend the same bytes: "
    "re-encode to evade while preserving intent — URL/double-encode suspicious tokens (../ -> %2e%2e%2f or "
    "%252e%252e%252f ; ' -> %27 ; space -> + ), vary keyword case (UnIoN), insert inline comments (UN/**/ION), "
    "or move the payload to an alternate parameter/header. Keep the same exploit class and target path.\n"
    'Reply with ONLY a JSON object, no prose, no markdown fences, keys: '
    '"vuln" (LFI|SSRF|AUTH|SQLI|OTHER), "method" (GET|POST), '
    '"path" (request path incl. query string, url-encoded as needed), '
    '"headers" (object of extra request headers, may be empty), '
    '"body" (request body string, empty if none), '
    '"reason" (one short sentence). Do not include the host; path only.'
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
        if not self._budget.try_reserve_llm(self._max_calls):
            return None  # 예산 소진 → 결정론 경로로 (검사·예약 원자적, 병렬 초과 방지)

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

        payload = json.dumps({
            "model": model_id,
            "temperature": 0,
            "max_completion_tokens": 300,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
        })
        api_key = self._store.resolve(self._key_handle)  # 원문은 여기서만
        resp = self._egress.request(
            Capability.LLM, "POST",
            self._config.llm_base_url + "/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            body=payload, timeout=LLM_TIMEOUT,
        )
        # 호출 수는 try_reserve_llm에서 이미 원자적으로 예약됨. 여기선 토큰만 가산.
        if resp.status != 200:
            return None
        try:
            obj = json.loads(resp.body)
            content = obj["choices"][0]["message"]["content"]
            self._budget.add_llm(0, int(obj.get("usage", {}).get("total_tokens", 0) or 0))
        except Exception:
            return None
        return parse_exploit(content)
