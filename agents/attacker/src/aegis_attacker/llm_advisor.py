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

MAX_LLM_CALLS_PER_ROUND = 160  # 라운드 LLM 호출 안전 상한(주최 200 이하). 예산 여유가 크고
# flag 1개 > 토큰(§0.2)이므로, 결정론이 못 뚫는 표적에 LLM 공략을 상한으로 조기 차단하지 않는다.
# single-flight·결정론 우선으로 쉬운 표적의 실사용은 여전히 낮다.
LLM_TIMEOUT = 20.0

# 실패가 쌓이면 더 센 모델로 승급한다(cheap-first). 동점 시 토큰 비용이 적은 팀이
# 이기므로(운영세칙 제22조) 값비싼 모델은 저비용 모델이 막혔을 때만 쓴다.
ESCALATION_MODELS = ("gpt-4.1", "gpt-5.2")


def escalated_model(base: str, level: int) -> str:
    if level <= 0:
        return base
    return ESCALATION_MODELS[min(level - 1, len(ESCALATION_MODELS) - 1)]

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
        if not self._budget.try_reserve_llm(self._max_calls):
            return None  # 예산 소진 → 결정론 경로로 (검사·예약 원자적, 병렬 초과 방지)

        # 현재 저장된 모든 비밀 원문을 프롬프트에서 제거(플러스 FLAG 정규식).
        redactor = Redactor(self._store.secrets_snapshot())
        hint_line = "Priority hints: " + ", ".join(h.value for h in hints) if hints else ""
        observed = feedback or banner
        user_content = redactor.scrub("\n".join(x for x in (hint_line, observed) if x))

        payload = json.dumps({
            "model": model or self._config.llm_model,
            "temperature": 0,
            "max_tokens": 300,
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
