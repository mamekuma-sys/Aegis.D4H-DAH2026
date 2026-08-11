import unittest

from aegis_attacker.models import (
    Endpoint,
    FinalsPhaseHint,
    Observation,
    ObservedServiceProfile,
    Scenario,
    ScenarioHypothesis,
)


class TestEndpoint(unittest.TestCase):
    def test_valid(self):
        ep = Endpoint("team2.lig.internal", 8082)
        self.assertEqual(ep.base_url(), "http://team2.lig.internal:8082")
        self.assertEqual(ep.key(), "team2.lig.internal:8082")

    def test_empty_host_rejected(self):
        with self.assertRaises(ValueError):
            Endpoint("", 80)

    def test_port_range_rejected(self):
        with self.assertRaises(ValueError):
            Endpoint("h", 0)
        with self.assertRaises(ValueError):
            Endpoint("h", 70000)

    def test_frozen_hashable(self):
        # Endpoint 는 집합/딕셔너리 키로 쓸 수 있어야 한다(중복 관측 방지).
        s = {Endpoint("h", 1), Endpoint("h", 1), Endpoint("h", 2)}
        self.assertEqual(len(s), 2)


class TestFinalsPhaseHint(unittest.TestCase):
    def test_requires_evidence(self):
        # 증거 참조 없이는 힌트를 만들 수 없다(§9.6).
        with self.assertRaises(ValueError):
            FinalsPhaseHint(2, 2, "reason", "")
        with self.assertRaises(ValueError):
            FinalsPhaseHint(2, 2, "", "evid")

    def test_phase_layer_range(self):
        with self.assertRaises(ValueError):
            FinalsPhaseHint(5, 2, "r", "e")
        with self.assertRaises(ValueError):
            FinalsPhaseHint(2, 9, "r", "e")

    def test_valid(self):
        h = FinalsPhaseHint(2, 2, "MCS 배너", "obs-1")
        self.assertEqual(h.finals_phase, 2)


class TestObservation(unittest.TestCase):
    def test_no_response_flag(self):
        obs = Observation(Endpoint("h", 1), "fp", status=0)
        self.assertTrue(obs.no_response)
        obs2 = Observation(Endpoint("h", 1), "fp", status=200)
        self.assertFalse(obs2.no_response)


class TestProfile(unittest.TestCase):
    def test_add_evidence_dedup(self):
        p = ObservedServiceProfile(Endpoint("h", 1))
        p.add_evidence("banner:URL Fetcher")
        p.add_evidence("banner:URL Fetcher")
        p.add_evidence("")
        self.assertEqual(p.evidence, ["banner:URL Fetcher"])
        self.assertIsNone(p.finals_phase_hint)


class TestHypothesis(unittest.TestCase):
    def test_active_requires_evidence_and_no_stop(self):
        h = ScenarioHypothesis(Scenario.S1)
        self.assertFalse(h.active)  # 증거 없음
        h.activation_evidence.append("Set-Cookie 관측")
        self.assertTrue(h.active)
        h.stop_reason = "예산 소진"
        self.assertFalse(h.active)


if __name__ == "__main__":
    unittest.main()
