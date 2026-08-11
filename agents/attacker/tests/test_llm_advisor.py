import json
import unittest

from aegis_attacker.config import AttackerConfig
from aegis_attacker.llm_advisor import LLMAdvisor
from aegis_attacker.models import RoundBudget, VulnClass
from aegis_attacker.observation import HttpResponse


def chat_response(content, tokens=42, status=200):
    body = json.dumps({
        "choices": [{"message": {"content": content}}],
        "usage": {"total_tokens": tokens},
    })
    return HttpResponse(status, body, {})


class RecordingHttp:
    def __init__(self, response):
        self.response = response
        self.last_body = None
        self.calls = 0

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        self.calls += 1
        self.last_body = body
        return self.response


CFG = AttackerConfig(
    targets=("team2.lig.internal",), ports=(8082,),
    submit_url="http://backend:4100/submit", submit_token="tok-team1-secret",
    llm_base_url="http://litellm.lig.internal:4000", llm_api_key="sk-team1-secret",
    llm_model="gpt-4o-mini",
)


class TestLLMAdvisor(unittest.TestCase):
    def test_advise_returns_parsed_exploit(self):
        http = RecordingHttp(chat_response('{"vuln":"SSRF","path":"/fetch?url=127.0.0.1"}'))
        budget = RoundBudget()
        adv = LLMAdvisor(http, CFG, budget)
        out = adv.advise_exploit("URL Fetcher /fetch", "", [VulnClass.SSRF])
        self.assertEqual(out["path"], "/fetch?url=127.0.0.1")
        self.assertEqual(budget.llm_calls, 1)
        self.assertEqual(budget.llm_tokens, 42)

    def test_prompt_redacts_flag_and_secrets(self):
        http = RecordingHttp(chat_response('{"path":"/x"}'))
        adv = LLMAdvisor(http, CFG, RoundBudget())
        feedback = "prev body: FLAG{leak} key=sk-team1-secret token=tok-team1-secret"
        adv.advise_exploit("banner", feedback, [])
        self.assertNotIn("FLAG{leak}", http.last_body)
        self.assertNotIn("sk-team1-secret", http.last_body)
        self.assertNotIn("tok-team1-secret", http.last_body)
        self.assertIn("[FLAG]", http.last_body)

    def test_budget_cap_returns_none(self):
        http = RecordingHttp(chat_response('{"path":"/x"}'))
        budget = RoundBudget(llm_calls=5)
        adv = LLMAdvisor(http, CFG, budget, max_calls=5)
        self.assertIsNone(adv.advise_exploit("b", "", []))
        self.assertEqual(http.calls, 0)  # 호출 자체 안 함

    def test_non_200_returns_none(self):
        http = RecordingHttp(chat_response("x", status=500))
        adv = LLMAdvisor(http, CFG, RoundBudget())
        self.assertIsNone(adv.advise_exploit("b", "", []))

    def test_no_api_key_returns_none(self):
        cfg = AttackerConfig(targets=("h",), ports=(80,), llm_api_key="")
        http = RecordingHttp(chat_response('{"path":"/x"}'))
        adv = LLMAdvisor(http, cfg, RoundBudget())
        self.assertIsNone(adv.advise_exploit("b", "", []))
        self.assertEqual(http.calls, 0)


if __name__ == "__main__":
    unittest.main()
