import json
import unittest

from aegis_attacker.flags import flag_fingerprint
from aegis_attacker.models import RoundBudget, SubmitState
from aegis_attacker.round_report import RoundReport


class TestRoundReport(unittest.TestCase):
    def test_counts_and_summary(self):
        r = RoundReport(budget=RoundBudget(llm_calls=3, llm_tokens=120))
        r.record_observation()
        r.record_observation()
        r.record_request()
        h1 = flag_fingerprint("FLAG{a}")
        h2 = flag_fingerprint("FLAG{b}")
        r.record_submit(h1, SubmitState.ACCEPTED)
        r.record_submit(h2, SubmitState.ACCEPTED)
        r.record_submit(flag_fingerprint("FLAG{c}"), SubmitState.DUPLICATE)
        s = r.summary()
        self.assertEqual(s["endpoints_observed"], 2)
        self.assertEqual(s["requests_made"], 1)
        self.assertEqual(s["accepted_count"], 2)
        self.assertEqual(s["submit_states"]["accepted"], 2)
        self.assertEqual(s["submit_states"]["duplicate"], 1)
        self.assertEqual(s["llm_calls"], 3)
        self.assertEqual(s["llm_tokens"], 120)

    def test_summary_has_no_plaintext_flag(self):
        r = RoundReport()
        r.record_submit(flag_fingerprint("FLAG{secret}"), SubmitState.ACCEPTED)
        blob = json.dumps(r.summary())
        self.assertNotIn("FLAG{secret}", blob)
        self.assertNotIn("secret", blob)  # 해시 접두만 노출

    def test_accepted_dedup_by_hash(self):
        r = RoundReport()
        h = flag_fingerprint("FLAG{same}")
        r.record_submit(h, SubmitState.ACCEPTED)
        r.record_submit(h, SubmitState.ACCEPTED)
        self.assertEqual(r.accepted_count(), 1)


if __name__ == "__main__":
    unittest.main()
