import json
import unittest
from dataclasses import replace

from aegis_attacker.config import (
    DEFAULT_LLM_FALLBACK_MODEL,
    DEFAULT_LLM_MODEL,
    AttackerConfig,
)
from aegis_attacker.egress import EgressGateway
from aegis_attacker.llm_advisor import (
    LLM_MAX_COMPLETION_TOKENS,
    LLM_REASONING_EFFORT,
    LLMAdvisor,
    MAX_LLM_USER_CONTENT_BYTES,
    SUPPORTED_LLM_MODELS,
)
from aegis_attacker.models import Capability, RoundBudget, VulnClass
from aegis_attacker.observation import HttpResponse
from aegis_attacker.secrets import KIND_LLM_KEY, KIND_SUBMIT_TOKEN, RoundSecretStore

LLM_URL_HOST = ("litellm.lig.internal", 4000)
ALLOW = {Capability.LLM: {LLM_URL_HOST}}
CFG = AttackerConfig(
    targets=("t2",), ports=(8082,),
    submit_url="http://backend:4100/submit", submit_token="tok-team1-secret",
    llm_base_url="http://litellm.lig.internal:4000", llm_api_key="sk-team1-secret",
    llm_model="gpt-4o-mini",
)
SOL_CFG = replace(CFG, llm_model=DEFAULT_LLM_MODEL)
PRO_CFG = replace(CFG, llm_model="gpt-5.4-pro")


def chat_response(content, tokens=42, status=200, finish_reason=None):
    choice = {"message": {"content": content}}
    if finish_reason is not None:
        choice["finish_reason"] = finish_reason
    body = json.dumps({"choices": [choice],
                       "usage": {"total_tokens": tokens}})
    return HttpResponse(status, body, {})


class RecordingTransport:
    def __init__(self, response):
        self.responses = list(response) if isinstance(response, (list, tuple)) else [response]
        self.last_body = None
        self.last_headers = None
        self.bodies = []
        self.timeouts = []
        self.calls = 0

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        self.calls += 1
        self.last_body = body
        self.last_headers = headers
        self.bodies.append(body)
        self.timeouts.append(timeout)
        response = self.responses[min(self.calls - 1, len(self.responses) - 1)]
        if isinstance(response, BaseException):
            raise response
        return response


def make_advisor(response, budget=None, with_key=True, max_calls=200, config=CFG):
    transport = RecordingTransport(response)
    gw = EgressGateway(transport, ALLOW)
    store = RoundSecretStore("r1")
    store.put(KIND_SUBMIT_TOKEN, "tok-team1-secret")  # snapshot 에 포함 → 프롬프트에서 제거
    key_handle = store.put(KIND_LLM_KEY, "sk-team1-secret") if with_key else None
    adv = LLMAdvisor(
        gw, config, budget or RoundBudget(), store, key_handle, max_calls=max_calls
    )
    return adv, transport


class TestLLMAdvisor(unittest.TestCase):
    def test_returns_parsed_exploit(self):
        adv, _ = make_advisor(chat_response('{"vuln":"SSRF","path":"/fetch?url=127.0.0.1"}'))
        out = adv.advise_exploit("URL Fetcher /fetch", "", [VulnClass.SSRF])
        self.assertEqual(out["path"], "/fetch?url=127.0.0.1")

    def test_budget_increments(self):
        b = RoundBudget()
        adv, _ = make_advisor(chat_response('{"path":"/x"}'), budget=b)
        adv.advise_exploit("b", "", [])
        self.assertEqual(b.llm_calls, 1)
        self.assertEqual(b.llm_tokens, 42)

    def test_prompt_redacts_flag_and_secrets(self):
        adv, transport = make_advisor(chat_response('{"path":"/x"}'))
        feedback = "prev: FLAG{leak} key=sk-team1-secret token=tok-team1-secret"
        adv.advise_exploit("banner", feedback, [])
        self.assertNotIn("FLAG{leak}", transport.last_body)
        self.assertNotIn("sk-team1-secret", transport.last_body)
        self.assertNotIn("tok-team1-secret", transport.last_body)

    def test_prompt_bounds_untrusted_observation_while_preserving_edges(self):
        adv, transport = make_advisor(chat_response('{"path":"/x"}'))
        banner = "BANNER_START\n" + ("a" * MAX_LLM_USER_CONTENT_BYTES)
        feedback = ("z" * MAX_LLM_USER_CONTENT_BYTES) + "\nFEEDBACK_END"

        adv.advise_exploit(banner, feedback, [])

        payload = json.loads(transport.last_body)
        user_content = payload["messages"][1]["content"]
        self.assertLessEqual(
            len(user_content.encode("utf-8")), MAX_LLM_USER_CONTENT_BYTES
        )
        self.assertIn("BANNER_START", user_content)
        self.assertIn("FEEDBACK_END", user_content)

    def test_key_sent_via_egress_auth(self):
        adv, transport = make_advisor(chat_response('{"path":"/x"}'))
        adv.advise_exploit("b", "", [])
        self.assertEqual(transport.last_headers["Authorization"], "Bearer sk-team1-secret")

    def test_uses_official_completion_token_parameter(self):
        adv, transport = make_advisor(chat_response('{"path":"/x"}'))
        adv.advise_exploit("b", "", [])
        payload = json.loads(transport.last_body)
        self.assertEqual(payload["max_completion_tokens"], LLM_MAX_COMPLETION_TOKENS)
        self.assertNotIn("max_tokens", payload)

    def test_primary_chat_uses_temperature_without_reasoning(self):
        adv, transport = make_advisor(
            chat_response('{"path":"/x"}'), config=SOL_CFG
        )
        adv.advise_exploit("b", "", [])
        payload = json.loads(transport.last_body)
        self.assertEqual(payload["model"], DEFAULT_LLM_MODEL)
        self.assertEqual(payload["temperature"], 0)
        self.assertEqual(payload["messages"][0]["role"], "system")
        self.assertNotIn("reasoning_effort", payload)

    def test_pro_model_omits_unsupported_temperature(self):
        adv, transport = make_advisor(
            chat_response('{"path":"/x"}'), config=PRO_CFG
        )
        adv.advise_exploit("b", "", [], model="gpt-5.4-pro")
        payload = json.loads(transport.last_body)
        self.assertEqual(payload["model"], "gpt-5.4-pro")
        self.assertNotIn("temperature", payload)

    def test_gpt56_uses_reasoning_and_developer_message(self):
        adv, transport = make_advisor(
            chat_response('{"path":"/x"}'), config=SOL_CFG
        )
        adv.advise_exploit("b", "", [], model="gpt-5.6-terra")
        payload = json.loads(transport.last_body)
        self.assertEqual(payload["model"], "gpt-5.6-terra")
        self.assertEqual(payload["reasoning_effort"], LLM_REASONING_EFFORT)
        self.assertEqual(payload["messages"][0]["role"], "developer")
        self.assertNotIn("temperature", payload)

    def test_legacy_override_preserves_temperature_without_reasoning_parameter(self):
        adv, transport = make_advisor(chat_response('{"path":"/x"}'))
        adv.advise_exploit("b", "", [])
        payload = json.loads(transport.last_body)
        self.assertEqual(payload["temperature"], 0)
        self.assertEqual(payload["messages"][0]["role"], "system")
        self.assertNotIn("reasoning_effort", payload)

    def test_chat_transport_failure_falls_back_to_sol(self):
        budget = RoundBudget()
        adv, transport = make_advisor(
            [TimeoutError("upstream timeout"), chat_response('{"path":"/fallback"}')],
            budget=budget,
            config=SOL_CFG,
        )

        out = adv.advise_exploit("b", "", [])

        self.assertEqual(out["path"], "/fallback")
        self.assertEqual(
            [json.loads(body)["model"] for body in transport.bodies],
            [DEFAULT_LLM_MODEL, DEFAULT_LLM_FALLBACK_MODEL],
        )
        first, second = (json.loads(body) for body in transport.bodies)
        self.assertEqual(first["temperature"], 0)
        self.assertEqual(second["reasoning_effort"], LLM_REASONING_EFFORT)
        self.assertEqual(transport.timeouts, [45.0, 45.0])
        self.assertEqual(budget.llm_calls, 2)
        self.assertEqual(budget.llm_tokens, 42)

    def test_sol_invalid_response_falls_back_and_counts_both_usage_records(self):
        budget = RoundBudget()
        adv, transport = make_advisor(
            [chat_response("not-json", tokens=7), chat_response('{"path":"/fallback"}')],
            budget=budget,
            config=SOL_CFG,
        )

        out = adv.advise_exploit("b", "", [])

        self.assertEqual(out["path"], "/fallback")
        self.assertEqual(transport.calls, 2)
        self.assertEqual(budget.llm_calls, 2)
        self.assertEqual(budget.llm_tokens, 49)

    def test_sol_length_finish_reason_falls_back(self):
        adv, transport = make_advisor(
            [
                chat_response('{"path":"/truncated"}', finish_reason="length"),
                chat_response('{"path":"/fallback"}'),
            ],
            config=SOL_CFG,
        )
        self.assertEqual(adv.advise_exploit("b", "", [])["path"], "/fallback")
        self.assertEqual(transport.calls, 2)

    def test_sol_transient_status_falls_back_but_bad_request_does_not(self):
        adv, transient = make_advisor(
            [chat_response("busy", status=503), chat_response('{"path":"/fallback"}')],
            config=SOL_CFG,
        )
        self.assertEqual(adv.advise_exploit("b", "", [])["path"], "/fallback")
        self.assertEqual(transient.calls, 2)

        adv, bad_request = make_advisor(
            [chat_response("bad", status=400), chat_response('{"path":"/unused"}')],
            config=SOL_CFG,
        )
        self.assertIsNone(adv.advise_exploit("b", "", []))
        self.assertEqual(bad_request.calls, 1)

    def test_fallback_respects_remaining_round_call_budget(self):
        budget = RoundBudget()
        adv, transport = make_advisor(
            TimeoutError("upstream timeout"),
            budget=budget,
            max_calls=1,
            config=SOL_CFG,
        )
        self.assertIsNone(adv.advise_exploit("b", "", []))
        self.assertEqual(transport.calls, 1)
        self.assertEqual(budget.llm_calls, 1)

    def test_explicit_non_pro_model_does_not_switch_to_fallback(self):
        adv, transport = make_advisor(
            [chat_response("busy", status=503), chat_response('{"path":"/unused"}')]
        )
        self.assertIsNone(adv.advise_exploit("b", "", [], model="gpt-4.1-mini"))
        self.assertEqual(transport.calls, 1)

    def test_budget_cap_returns_none(self):
        adv, transport = make_advisor(chat_response('{"path":"/x"}'),
                                      budget=RoundBudget(llm_calls=5), max_calls=5)
        self.assertIsNone(adv.advise_exploit("b", "", []))
        self.assertEqual(transport.calls, 0)

    def test_non_200_returns_none(self):
        adv, _ = make_advisor(chat_response("x", status=500))
        self.assertIsNone(adv.advise_exploit("b", "", []))

    def test_no_key_handle_returns_none(self):
        adv, transport = make_advisor(chat_response('{"path":"/x"}'), with_key=False)
        self.assertIsNone(adv.advise_exploit("b", "", []))
        self.assertEqual(transport.calls, 0)

    def test_responses_model_is_translated_by_proxy_chat_endpoint(self):
        adv, transport = make_advisor(chat_response('{"path":"/x"}'))
        self.assertIsNotNone(adv.advise_exploit("b", "", [], model="gpt-5-pro"))
        self.assertEqual(transport.calls, 1)
        self.assertEqual(json.loads(transport.last_body)["model"], "gpt-5-pro")

    def test_supported_model_catalog_matches_finals_contract(self):
        from pathlib import Path

        contract_path = (
            Path(__file__).resolve().parents[3]
            / "contracts" / "llm" / "model-quotas.json"
        )
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        expected = {item["id"] for item in contract["models"]}
        priced = {item["id"] for item in contract["price_schedule"]["models"]}
        self.assertEqual(set(SUPPORTED_LLM_MODELS), expected)
        self.assertEqual(priced, expected)
        self.assertEqual(contract["proxy_request_endpoint"], "/v1/chat/completions")
        prices = {
            item["id"]: item for item in contract["price_schedule"]["models"]
        }
        self.assertEqual(prices[DEFAULT_LLM_MODEL]["output"], 15)
        self.assertEqual(prices[DEFAULT_LLM_FALLBACK_MODEL]["output"], 30)
        self.assertEqual(contract["team_total_budget_usd"], 1360)


if __name__ == "__main__":
    unittest.main()
