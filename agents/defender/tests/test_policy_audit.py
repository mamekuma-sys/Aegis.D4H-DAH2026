"""PolicyBundle 검증과 로딩 순서 테스트.

설계 §10.2, §15.3 PolicyBundle 검증.

강등과 거부의 구분이 이 파일의 주제다. 기준은 "그 rule을 안전하게 무력화할 수
있는가"이며, 무력화할 수 있으면 강등하고 bundle 전체의 해석을 신뢰할 수 없으면
거부한다.
"""

import json
import os
import tempfile
import unittest

from aegis_defender.rules import (
    PolicyValidationError,
    PromotionState,
    compile_bundle,
    load_policy,
    validate_pattern,
)

from .fakes import minimal_bundle, rule_document

BASELINE = ["6/80"]
_POLICY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policy"))


class TestBundleRejection(unittest.TestCase):
    """bundle 전체를 거부해야 하는 구조 오류."""

    def _reject(self, document):
        with self.assertRaises(PolicyValidationError):
            compile_bundle(document)

    def test_unsupported_schema_version(self):
        document = minimal_bundle()
        document["schema_version"] = 99
        self._reject(document)

    def test_duplicate_rule_id(self):
        self._reject(minimal_bundle(
            rules=[rule_document("dup"), rule_document("dup", pattern="union")],
            baseline_profiles=BASELINE,
        ))

    def test_parser_version_ahead_of_runtime(self):
        self._reject(minimal_bundle(rules=[rule_document("r", parser_version=99)]))

    def test_unknown_promotion_state(self):
        self._reject(minimal_bundle(rules=[rule_document("r", promotion_state="ENABLED")]))

    def test_unknown_kind(self):
        self._reject(minimal_bundle(rules=[rule_document("r", kind="magic")]))

    def test_canary_fraction_out_of_range(self):
        self._reject(minimal_bundle(rules=[rule_document("r", canary_fraction=1.5)]))

    def test_canary_without_seed(self):
        self._reject(minimal_bundle(rules=[rule_document(
            "r", promotion_state="CANARY", canary_fraction=0.2, canary_seed=""
        )]))

    def test_canary_without_fraction(self):
        self._reject(minimal_bundle(rules=[rule_document(
            "r", promotion_state="CANARY", canary_fraction=0.0, canary_seed="s"
        )]))

    def test_port_out_of_range(self):
        self._reject(minimal_bundle(rules=[rule_document("r", ports=[70000])]))

    def test_missing_promotion_cohort(self):
        document = rule_document("r")
        document.pop("promotion_cohort")
        self._reject(minimal_bundle(rules=[document]))

    def test_contradictory_promotion_cohort(self):
        # 같은 cohort 인데 promoted_in_bundle 이 다르면 어느 이미지에서 승격됐는지
        # 추적할 수 없다.
        self._reject(minimal_bundle(rules=[
            rule_document("r1", promoted_in_bundle="bundle-a"),
            rule_document("r2", pattern="union", promoted_in_bundle="bundle-b"),
        ]))

    def test_missing_evidence_field(self):
        document = rule_document("r")
        document.pop("negative_fixture_id")
        self._reject(minimal_bundle(rules=[document]))

    def test_missing_review_field(self):
        document = rule_document("r")
        document.pop("lead_review")
        self._reject(minimal_bundle(rules=[document]))

    def test_unparseable_expiry(self):
        self._reject(minimal_bundle(rules=[rule_document("r", expires_at="soon")]))

    def test_broken_regex(self):
        self._reject(minimal_bundle(rules=[rule_document("r", pattern="(?:unclosed")]))


class TestPatternSafety(unittest.TestCase):
    """§9.3 — catastrophic backtracking을 유발하는 패턴을 금지한다."""

    def _reject(self, pattern):
        with self.assertRaises(PolicyValidationError):
            validate_pattern(pattern, "test")

    def test_oversized_pattern(self):
        self._reject("a" * 600)

    def test_backreference(self):
        self._reject(r"(?:abc)\1")

    def test_capturing_group(self):
        self._reject(r"(abc)+")

    def test_nested_quantifier(self):
        self._reject(r"(?:a+)+")

    def test_excessive_repetition_bound(self):
        self._reject(r"a{5000}")

    def test_literal_parenthesis_is_allowed(self):
        # `sleep\(` 의 괄호는 구조가 아니라 리터럴이다.
        validate_pattern(r"sleep\(|benchmark\(", "test")

    def test_character_class_contents_are_not_structure(self):
        validate_pattern(r"%2[eE]%2[eE]", "test")

    def test_shipped_patterns_are_safe(self):
        with open(os.path.join(_POLICY_DIR, "active.json"), encoding="utf-8") as handle:
            document = json.load(handle)
        for rule in document["rules"]:
            if rule["kind"] == "payload_regex":
                validate_pattern(rule["pattern"], rule["rule_id"])


class TestDemotion(unittest.TestCase):
    """§10.2 — 무력화할 수 있는 문제는 거부가 아니라 강등이다."""

    def test_expired_rule_is_demoted(self):
        compiled, demotions = compile_bundle(minimal_bundle(
            rules=[rule_document("r-old", expires_at="2020-01-01T00:00:00Z")],
            baseline_profiles=BASELINE,
        ))
        self.assertIn("r-old:expired", demotions)
        self.assertIs(compiled.rules_by_id["r-old"].promotion_state, PromotionState.SHADOW)
        self.assertEqual(compiled.drop_capable_rule_count, 0)

    def test_unapproved_active_rule_is_demoted(self):
        compiled, demotions = compile_bundle(minimal_bundle(
            rules=[rule_document("r-unreviewed", lead_review="pending")],
            baseline_profiles=BASELINE,
        ))
        self.assertIn("r-unreviewed:review-not-approved", demotions)
        self.assertIs(
            compiled.rules_by_id["r-unreviewed"].promotion_state, PromotionState.SHADOW
        )

    def test_empty_baseline_disables_all_drop_rules(self):
        """§15.6 — 정상 profile이 비어 있으면 DROP rule이 활성화되지 않는다."""
        compiled, demotions = compile_bundle(minimal_bundle(
            rules=[rule_document("r-active"), rule_document("r-canary2", pattern="union",
                                                            promotion_state="CANARY",
                                                            canary_fraction=0.5,
                                                            canary_seed="s")],
            baseline_profiles=[],
        ))
        self.assertEqual(compiled.drop_capable_rule_count, 0)
        self.assertEqual(len(demotions), 2)
        for entry in demotions:
            self.assertTrue(entry.endswith(":no-baseline-profile"))

    def test_shadow_rules_are_untouched(self):
        compiled, demotions = compile_bundle(minimal_bundle(
            rules=[rule_document("r-shadow", promotion_state="SHADOW")],
            baseline_profiles=[],
        ))
        self.assertEqual(demotions, ())
        self.assertIs(compiled.rules_by_id["r-shadow"].promotion_state, PromotionState.SHADOW)


class TestLoadOrder(unittest.TestCase):
    """§10.2 — active → fallback → DROP rule 0개."""

    def _write(self, directory, name, document):
        with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
            json.dump(document, handle)

    def test_active_is_preferred(self):
        with tempfile.TemporaryDirectory() as directory:
            self._write(directory, "active.json", minimal_bundle(bundle_id="A"))
            self._write(directory, "fallback.json", minimal_bundle(bundle_id="B"))
            _, report = load_policy(directory)
            self.assertEqual(report.source, "active")
            self.assertEqual(report.bundle_id, "A")

    def test_invalid_active_falls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(directory, "active.json"), "w", encoding="utf-8") as handle:
                handle.write("{not json")
            self._write(directory, "fallback.json", minimal_bundle(bundle_id="B"))
            _, report = load_policy(directory)
            self.assertEqual(report.source, "fallback")
            self.assertEqual(report.bundle_id, "B")
            self.assertTrue(any(error.startswith("active:") for error in report.errors))

    def test_both_invalid_starts_with_zero_drop_rules(self):
        # 기동 실패로 만들지 않는다. HEARTBEAT 와 ACCEPT 경로가 살아 있는 것이
        # Broker fail-open 보다 낫다.
        with tempfile.TemporaryDirectory() as directory:
            compiled, report = load_policy(directory)
            self.assertEqual(report.source, "empty")
            self.assertEqual(compiled.drop_capable_rule_count, 0)
            self.assertEqual(report.errors, ("active:missing", "fallback:missing"))

    def test_shipped_bundle_enforces_l2_after_breach(self):
        """Phase 2 L2 유출 이후 승격된 태세(§16.2 관측기 종료). 로드 시 강등 없이
        차단 규칙이 켜지고, 정상 baseline과 zero-FP ACTIVE 규칙이 준비돼 있어야 한다.
        """
        compiled, report = load_policy(_POLICY_DIR)
        self.assertEqual(report.source, "active")
        self.assertEqual(report.demotions, ())  # 승인·baseline·미만료 → 강등 없이 집행
        self.assertGreater(report.drop_capable_rules, 0)
        self.assertEqual(compiled.baseline_profiles, frozenset({"6/8083", "6/8084"}))
        # zero-FP 서명은 ACTIVE, 중간 위험은 CANARY로만 승격한다.
        active_ids = {r.rule_id for r in compiled.rules_by_id.values()
                      if r.promotion_state is PromotionState.ACTIVE}
        self.assertEqual(active_ids, {"sig-file-read-001", "sig-sensitive-path-001"})
        # tcp 스캔 게이트와 flow-score는 본선 fixture 보정 전까지 SHADOW 유지.
        for rid in ("gate-tcp-null-001", "score-flow-risk-001"):
            self.assertIs(compiled.rules_by_id[rid].promotion_state, PromotionState.SHADOW)

    def test_shipped_fallback_is_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(_POLICY_DIR, "fallback.json"), encoding="utf-8") as source:
                document = json.load(source)
            self._write(directory, "fallback.json", document)
            _, report = load_policy(directory)
            self.assertEqual(report.source, "fallback")
            self.assertEqual(report.drop_capable_rules, 0)


class TestShippedBundleEnforcement(unittest.TestCase):
    """승격된 shipped bundle이 실제 hot path에서 공격은 DROP, 정상은 ACCEPT하는가."""

    def setUp(self):
        from aegis_defender.policy import HotPolicy
        compiled, _ = load_policy(_POLICY_DIR)
        self.policy = HotPolicy(policy=compiled, clock=lambda: 0.0)

    def _verdict(self, payload, dst_port=8083, src_port=51234):
        from aegis_defender.packet import parse_ip
        from .fakes import ipv4_tcp
        parsed = parse_ip(ipv4_tcp(payload, src_port=src_port, dst_port=dst_port))
        return self.policy.decide(1, parsed, 0.0)

    def test_active_rules_drop_attacks(self):
        from aegis_defender.protocol import VERDICT_DROP
        drops = [
            b"GET /read?file=/etc/passwd HTTP/1.1\r\n\r\n",       # LFI (file-read)
            b"GET /fetch?url=file:///flag HTTP/1.1\r\n\r\n",       # SSRF file:// (file-read)
            b"GET /.git/config HTTP/1.1\r\n\r\n",                  # 소스 유출 (sensitive-path)
            b"GET /flag HTTP/1.1\r\n\r\n",                          # flag 경로 (sensitive-path)
        ]
        for payload in drops:
            self.assertEqual(self._verdict(payload).verdict, VERDICT_DROP, payload)

    def test_normal_traffic_accepts(self):
        from aegis_defender.protocol import VERDICT_ACCEPT
        normal = [
            b"GET / HTTP/1.1\r\nHost: team1.lig.internal\r\n\r\n",
            b"GET /admin HTTP/1.1\r\nCookie: session=abc123\r\n\r\n",     # 정상 admin+쿠키
            b"POST /login HTTP/1.1\r\n\r\nuser=bob&password=hunter2",     # 정상 로그인
            b"GET /proxy?target=report HTTP/1.1\r\n\r\n",                 # 내부 IP 없는 정상 proxy
        ]
        for payload in normal:
            self.assertEqual(self._verdict(payload).verdict, VERDICT_ACCEPT, payload)

    def test_canary_rules_drop_a_fraction(self):
        from aegis_defender.protocol import VERDICT_DROP
        # CANARY는 flow별 결정론 bucket이므로 여러 flow 중 일부만 DROP된다(전부도 0도 아님).
        drops = sum(
            1 for i in range(200)
            if self._verdict(b"GET /item?id=1 union select 1,2,3 HTTP/1.1\r\n\r\n",
                             src_port=20000 + i).verdict == VERDICT_DROP
        )
        self.assertGreater(drops, 0)
        self.assertLess(drops, 200)

    def test_flag_egress_blocks_some_exfil_responses(self):
        from aegis_defender.protocol import VERDICT_DROP
        # 응답(src_port=8083)에 담긴 FLAG{...} 유출을 wildcard 규칙이 일부 flow에서 DROP.
        drops = sum(
            1 for i in range(200)
            if self._verdict(b"HTTP/1.1 200 OK\r\n\r\nFLAG{leaked_%d}" % i,
                             src_port=8083, dst_port=40000 + i).verdict == VERDICT_DROP
        )
        self.assertGreater(drops, 0)


class TestRuntimeCannotMutatePolicy(unittest.TestCase):
    """§10.3 — 런타임은 어떤 방향으로도 승격 상태를 바꾸지 않는다."""

    def test_compiled_policy_has_no_mutation_api(self):
        compiled, _ = compile_bundle(minimal_bundle(
            rules=[rule_document("r")], baseline_profiles=BASELINE
        ))
        forbidden = ("promote", "demote", "rollback", "set_state", "update", "reload")
        for name in forbidden:
            self.assertFalse(hasattr(compiled, name), f"{name} 이 존재해서는 안 된다")

    def test_rule_is_frozen(self):
        compiled, _ = compile_bundle(minimal_bundle(
            rules=[rule_document("r")], baseline_profiles=BASELINE
        ))
        rule = compiled.rules_by_id["r"]
        with self.assertRaises(Exception):
            rule.promotion_state = PromotionState.SHADOW

    def test_rules_mapping_is_read_only(self):
        compiled, _ = compile_bundle(minimal_bundle(
            rules=[rule_document("r")], baseline_profiles=BASELINE
        ))
        with self.assertRaises(TypeError):
            compiled.rules_by_id["new"] = None


if __name__ == "__main__":
    unittest.main()
