import unittest

from aegis_attacker.models import (
    Capability,
    Endpoint,
    EvidenceRef,
    FinalsPhase,
    FinalsPhaseHint,
    MissionState,
    Observation,
    ObservedServiceProfile,
    RoundBudget,
    S4ChainStage,
    Scenario,
    ScenarioHypothesis,
    SideEffectClass,
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

    def test_endpoint_id_stable(self):
        self.assertEqual(Endpoint("t2", 8082).endpoint_id, "t2:8082")

    def test_scheme_changes_transport_but_not_endpoint_identity(self):
        plain = Endpoint("t2", 443)
        secure = Endpoint("t2", 443, scheme="https")
        self.assertEqual(secure.base_url(), "https://t2:443")
        self.assertEqual(plain, secure)
        self.assertEqual(hash(plain), hash(secure))
        self.assertEqual(secure.endpoint_id, "t2:443")

    def test_unknown_scheme_rejected(self):
        with self.assertRaises(ValueError):
            Endpoint("t2", 443, scheme="tcp")


class TestEvidenceRef(unittest.TestCase):
    def _ref(self, expires=100.0):
        return EvidenceRef("e1", "r1", "t2:8082", 0.0, expires, "fp")

    def test_valid_when_matching_and_fresh(self):
        self.assertTrue(self._ref().valid_at(10.0, "r1", "t2:8082"))

    def test_invalid_when_expired(self):
        self.assertFalse(self._ref(expires=5.0).valid_at(10.0, "r1", "t2:8082"))

    def test_invalid_on_round_or_endpoint_mismatch(self):
        self.assertFalse(self._ref().valid_at(10.0, "r2", "t2:8082"))
        self.assertFalse(self._ref().valid_at(10.0, "r1", "other:1"))


class TestEnums(unittest.TestCase):
    def test_capabilities(self):
        self.assertEqual({c.value for c in Capability},
                         {"ATTACK_TARGET", "SUBMIT", "LLM"})

    def test_side_effect_default_read_only(self):
        self.assertEqual(SideEffectClass.READ_ONLY.value, "READ_ONLY")


class TestPhaseTermSeparation(unittest.TestCase):
    """FinalsPhase·S4ChainStage·MissionState 는 서로 다른 타입·용어다(§7.1·§9.15)."""

    def test_distinct_types(self):
        self.assertNotEqual(type(FinalsPhase.P1), type(S4ChainStage.STAGE1))
        self.assertNotEqual(type(FinalsPhase.P1), type(MissionState.CRUISE))
        self.assertFalse(isinstance(S4ChainStage.STAGE1, FinalsPhase))
        self.assertFalse(isinstance(MissionState.CRUISE, FinalsPhase))

    def test_finals_phase_1_to_4(self):
        self.assertEqual([p.value for p in FinalsPhase], [1, 2, 3, 4])

    def test_s4chainstage_1_to_5(self):
        self.assertEqual([s.value for s in S4ChainStage], [1, 2, 3, 4, 5])

    def test_same_number_not_equal_across_types(self):
        # 같은 숫자라도 FinalsPhase 1 과 S4ChainStage 1 을 동일시하지 않는다
        self.assertIsNot(FinalsPhase.P1, S4ChainStage.STAGE1)

    def test_mission_state_members(self):
        self.assertIn(MissionState.PRE_FLIGHT, MissionState)
        self.assertEqual(MissionState.RTL.value, "rtl")


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


class TestRoundBudget(unittest.TestCase):
    def test_try_reserve_llm_enforces_cap_atomically(self):
        b = RoundBudget()
        # 상한까지는 예약 성공하며 호출 수를 증가시킨다
        self.assertTrue(b.try_reserve_llm(2))
        self.assertTrue(b.try_reserve_llm(2))
        self.assertEqual(b.llm_calls, 2)
        # 상한 도달 후에는 실패하고 카운터를 더 올리지 않는다
        self.assertFalse(b.try_reserve_llm(2))
        self.assertEqual(b.llm_calls, 2)

    def test_reset_clears_all_counters(self):
        b = RoundBudget()
        b.request_count = 5
        b.submit_count = 3
        b.try_reserve_llm(100)
        b.add_llm(0, 42)
        b.reset()
        self.assertEqual(
            (b.request_count, b.submit_count, b.llm_calls, b.llm_tokens),
            (0, 0, 0, 0),
        )
        # 리셋 후 다시 상한만큼 예약 가능(라운드별 격리)
        self.assertTrue(b.try_reserve_llm(1))


if __name__ == "__main__":
    unittest.main()
