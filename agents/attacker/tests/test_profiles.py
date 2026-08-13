import unittest

from aegis_attacker.models import Endpoint, VulnClass
from aegis_attacker.profiles import (
    classify,
    latency_band,
    merge_observation,
    suggest_vuln_classes,
)

EP = Endpoint("team2.lig.internal", 8082)

# 스켈레톤 데모 챌린지 배너(본선 사실 아님, 인터페이스 예시).
BANNER_SSRF = "URL Fetcher — GET /fetch?url=<url>\nInternal service registry: GET /registry"
BANNER_AUTH = "Admin Portal — admin area at /admin. Get a session at /login first."
BANNER_SQLI = "Shop — GET /product?id=<n>\nbacked by SQLite."


class TestLatencyBand(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(latency_band(10), "fast")
        self.assertEqual(latency_band(100), "normal")
        self.assertEqual(latency_band(500), "slow")


class TestClassify(unittest.TestCase):
    def test_records_evidence_and_headers(self):
        p = classify(EP, 200, BANNER_AUTH, {"Set-Cookie": "session=abc"}, 40.0)
        self.assertEqual(p.status_codes, {200})
        self.assertEqual(p.latency_band, "fast")
        self.assertIn("Set-Cookie", p.redacted_header_hints)
        self.assertTrue(any(e.startswith("banner:") for e in p.evidence))
        self.assertTrue(any(e.startswith("header:") for e in p.evidence))
        self.assertIsNone(p.finals_phase_hint)  # 증거가 레이어를 확정하지 않음

    def test_error_signature_capture(self):
        p = classify(EP, 400, "sqlite error near: syntax error", {}, 20.0)
        self.assertIn("sqlite", p.error_signatures)
        self.assertIn("syntax error", p.error_signatures)

    def test_merge_accumulates(self):
        p = classify(EP, 200, BANNER_SQLI, {}, 20.0)
        merge_observation(p, 500, "no such table: sqlite_master", {"X-Flag": "1"})
        self.assertIn(500, p.status_codes)
        self.assertIn("X-Flag", p.redacted_header_hints)
        self.assertIn("sqlite", p.error_signatures)


class TestPerEndpointProfiles(unittest.TestCase):
    """UAV 근거를 UGV에 무근거 재사용하지 않는다 — 프로파일은 endpoint별로 독립(§9.15)."""

    def test_profiles_independent_per_endpoint(self):
        uav = Endpoint("team2.lig.internal", 8084)
        ugv = Endpoint("team2.lig.internal", 9001)
        p_uav = classify(uav, 200, "UAV telemetry service", {}, 20.0)
        p_ugv = classify(ugv, 200, "UGV walker service", {}, 20.0)
        self.assertIsNot(p_uav, p_ugv)
        self.assertEqual(p_uav.endpoint, uav)
        self.assertEqual(p_ugv.endpoint, ugv)
        self.assertNotIn("banner:UAV telemetry service", p_ugv.evidence)


class TestSuggestVulnClasses(unittest.TestCase):
    def test_ssrf_banner(self):
        self.assertIn(VulnClass.SSRF, suggest_vuln_classes(BANNER_SSRF))

    def test_auth_banner(self):
        self.assertIn(VulnClass.AUTH, suggest_vuln_classes(BANNER_AUTH))

    def test_sqli_banner(self):
        self.assertIn(VulnClass.SQLI, suggest_vuln_classes(BANNER_SQLI))

    def test_unknown_banner_returns_other(self):
        self.assertEqual(suggest_vuln_classes("hello world"), [VulnClass.OTHER])


if __name__ == "__main__":
    unittest.main()
