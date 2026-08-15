# L1 SSRF Blocking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Multi-agent dispatch is disabled for this task; execute inline on local `main`.

**Goal:** Activate one evidence-backed TCP/8082 rule that drops the observed L1 `helper-box:8080/secret` SSRF variants without blocking unrelated `/fetch` traffic.

**Architecture:** Keep the existing parser and `HotPolicy` unchanged. Add a port-scoped `payload_regex` rule to the shipped PolicyBundle, prove behavior through tests that load the real bundle, and include the new matcher in timing coverage. Keep all prior heuristic rules in `SHADOW`.

**Tech Stack:** Python 3.12 standard library, `unittest`, JSON PolicyBundle, PowerShell repository checks.

## Global Constraints

- Work directly on local `main` as explicitly requested; do not create a branch or worktree.
- Do not push to `origin/main`.
- Never commit PCAP, logs, flags, credentials, caches, or generated output.
- The defender synchronous path remains deterministic and contains no remote LLM calls.
- Scope enforcement to observed TCP destination port `8082`; do not infer layer identity from an unproven runtime address field.
- Do not block `/fetch`, User-Agent values, or NAT source IP by themselves.
- Record `owner_review=approved` and `lead_review=approved` because the user explicitly confirmed both approvals.
- Preserve unrelated untracked files.

---

### Task 1: Add shipped-policy regression tests

**Files:**
- Create: `agents/defender/tests/test_l1_ssrf_policy.py`

**Interfaces:**
- Consumes: `load_policy(policy_dir, now_epoch)`, `HotPolicy.decide`, `parse_ip`, and `tests.fakes.ipv4_tcp`.
- Produces: regression coverage for the three observed encodings, 100 negative/SLA requests, port scope, and shipped-bundle metadata.

- [ ] **Step 1: Write the failing test**

```python
"""실측 L1 SSRF hotfix의 shipped PolicyBundle 회귀 테스트."""

import os
import unittest

from aegis_defender.packet import parse_ip
from aegis_defender.policy import HotPolicy
from aegis_defender.protocol import VERDICT_ACCEPT, VERDICT_DROP
from aegis_defender.rules import PromotionState, load_policy

from .fakes import ipv4_tcp

_POLICY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policy"))
_ACTIVE_WINDOW_EPOCH = 1786764000.0
_RULE_ID = "sig-l1-helper-secret-001"
_REASON = "sig-l1-helper-secret"

_POSITIVE_PATHS = (
    "/fetch?url=http://helper-box:8080/secret",
    "/fetch?url=http%3A%2F%2Fhelper-box%3A8080%2Fsecret",
    "/%66%65%74%63%68?%75%72%6C=%68%74%74%70%3A%2F%2F%68%65%6C%70%65%72%2D%62%6F%78%3A%38%30%38%30%2F%73%65%63%72%65%74",
)

_NEGATIVE_PATHS = (
    "/",
    "/fetch",
    "/fetch?url=http://127.0.0.1:5000/registry",
    "/fetch?url=http://127.0.0.1:5000/health",
    "/fetch?url=http://example.invalid/",
)


class TestShippedL1SsrfPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiled, report = load_policy(_POLICY_DIR, now_epoch=_ACTIVE_WINDOW_EPOCH)
        cls.compiled = compiled
        cls.report = report
        cls.policy = HotPolicy(policy=compiled, clock=lambda: 0.0)

    def _decide(self, path, dst_port=8082, pkt_id=1):
        payload = (
            f"GET {path} HTTP/1.1\r\n"
            "Host: team1.lig.internal:8082\r\n"
            "User-Agent: fixture\r\n\r\n"
        ).encode("ascii")
        parsed = parse_ip(ipv4_tcp(payload, dst_port=dst_port))
        return self.policy.decide(pkt_id, parsed, 0.0)

    def test_observed_plain_and_encoded_variants_drop(self):
        for index, path in enumerate(_POSITIVE_PATHS, start=1):
            with self.subTest(path=path):
                decision = self._decide(path, pkt_id=index)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, _RULE_ID)
                self.assertEqual(decision.reason_code, _REASON)

    def test_round1_negative_and_sla_requests_accept_100_times(self):
        for index in range(100):
            path = _NEGATIVE_PATHS[index % len(_NEGATIVE_PATHS)]
            with self.subTest(index=index, path=path):
                self.assertEqual(self._decide(path, pkt_id=index).verdict, VERDICT_ACCEPT)

    def test_same_payload_on_non_l1_port_accepts(self):
        for index, path in enumerate(_POSITIVE_PATHS, start=1):
            with self.subTest(path=path):
                self.assertEqual(
                    self._decide(path, dst_port=8083, pkt_id=index).verdict,
                    VERDICT_ACCEPT,
                )

    def test_shipped_bundle_activates_only_the_l1_hotfix(self):
        self.assertEqual(self.report.source, "active")
        self.assertEqual(self.report.bundle_id, "defender-2026-08-15-l1-ssrf-hotfix")
        self.assertEqual(self.report.drop_capable_rules, 1)
        self.assertEqual(self.report.demotions, ())
        self.assertEqual(self.compiled.baseline_profiles, frozenset({"6/8082"}))
        self.assertIs(
            self.compiled.rules_by_id[_RULE_ID].promotion_state,
            PromotionState.ACTIVE,
        )
        for rule_id, rule in self.compiled.rules_by_id.items():
            if rule_id != _RULE_ID:
                self.assertIs(rule.promotion_state, PromotionState.SHADOW)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the targeted test and verify RED**

Run from `agents/defender`:

```powershell
python -m unittest tests.test_l1_ssrf_policy -v
```

Expected: failures show observed SSRF requests are `ACCEPT`, the hotfix rule is missing, and `drop_capable_rules` is `0`. Import or syntax errors are not an acceptable RED state.

---

### Task 2: Activate the minimal L1 rule

**Files:**
- Modify: `agents/defender/policy/active.json:3`
- Modify: `agents/defender/policy/active.json:5`
- Modify: `agents/defender/policy/active.json` after the existing final rule

**Interfaces:**
- Consumes: existing PolicyBundle schema and `payload_regex` matcher.
- Produces: bundle `defender-2026-08-15-l1-ssrf-hotfix` with exactly one drop-capable rule.

- [ ] **Step 1: Update bundle metadata**

Set:

```json
"bundle_id": "defender-2026-08-15-l1-ssrf-hotfix",
"generated_at": "2026-08-15T03:20:00Z",
"baseline_profiles": ["6/8082"]
```

- [ ] **Step 2: Append the approved rule**

```json
{
  "rule_id": "sig-l1-helper-secret-001",
  "kind": "payload_regex",
  "category": "ssrf",
  "reason_code": "sig-l1-helper-secret",
  "protocol": "tcp",
  "ports": [8082],
  "pattern": "helper-box(?::|%3a)8080(?:/|%2f)secret|%68%65%6c%70%65%72%2d%62%6f%78%3a%38%30%38%30%2f%73%65%63%72%65%74",
  "ignore_case": true,
  "promotion_state": "ACTIVE",
  "canary_fraction": 0.0,
  "canary_seed": "",
  "promotion_cohort": "p1-r4-l1-helper-ssrf",
  "promoted_in_bundle": "defender-2026-08-15-l1-ssrf-hotfix",
  "parser_version": 1,
  "profile_scope": ["6/8082"],
  "evidence_id": "PCAP-P1-R4-L1-20260815-030005",
  "positive_fixture_id": "P1-R4-L1-HELPER-SECRET-POS-001",
  "negative_fixture_id": "P1-R1-L1-HTTP-NEG-001",
  "sla_fixture_id": "P1-R1-L1-SLA-100-001",
  "expires_at": "2026-08-15T10:00:00Z",
  "rollback_condition": "공식 SLA가 직전 Round보다 하락하거나 정상 negative fixture가 하나라도 실패하면 직전 검증 이미지로 복귀",
  "owner_review": "approved",
  "lead_review": "approved"
}
```

- [ ] **Step 3: Run the targeted test and verify GREEN**

Run:

```powershell
python -m unittest tests.test_l1_ssrf_policy -v
```

Expected: 4 tests pass; the three positive variants drop, 100 negative/SLA requests accept, TCP/8083 accepts, and the bundle has one active rule with no demotions.

---

### Task 3: Align bundle audit and timing coverage

**Files:**
- Modify: `agents/defender/tests/test_policy_audit.py:218`
- Modify: `agents/defender/tests/test_timing.py:63`

**Interfaces:**
- Consumes: shipped active bundle metadata and the production hotfix regex.
- Produces: stable time-independent audit assertions and performance coverage that exercises the TCP/8082 matcher.

- [ ] **Step 1: Replace the obsolete zero-drop shipped-bundle test**

Use a fixed in-window epoch and assert exactly one active rule:

```python
def test_shipped_bundle_activates_only_reviewed_l1_hotfix(self):
    compiled, report = load_policy(_POLICY_DIR, now_epoch=1786764000.0)
    self.assertEqual(report.source, "active")
    self.assertEqual(report.bundle_id, "defender-2026-08-15-l1-ssrf-hotfix")
    self.assertEqual(report.drop_capable_rules, 1)
    self.assertEqual(report.demotions, ())
    self.assertEqual(compiled.baseline_profiles, frozenset({"6/8082"}))
    for rule_id, rule in compiled.rules_by_id.items():
        expected = PromotionState.ACTIVE if rule_id == "sig-l1-helper-secret-001" else PromotionState.SHADOW
        self.assertIs(rule.promotion_state, expected)
```

- [ ] **Step 2: Exercise the new matcher in timing tests**

Add the hotfix rule to `build_policy`:

```python
rule_document(
    "r-l1-ssrf",
    pattern=(
        "helper-box(?::|%3a)8080(?:/|%2f)secret|"
        "%68%65%6c%70%65%72%2d%62%6f%78%3a%38%30%38%30%2f%73%65%63%72%65%74"
    ),
    category="ssrf",
    ports=[8082],
),
```

In `sample_frames`, make each twentieth attack sample use destination port `8082`; keep normal samples on port `80`.

- [ ] **Step 3: Run policy and timing tests**

Run:

```powershell
python -m unittest tests.test_policy tests.test_policy_audit tests.test_l1_ssrf_policy -v
python -m unittest tests.test_timing -v
```

Expected: all tests pass, timing reports p50 below 150us, p99 below 500us, and zero verdicts exceed 300ms.

---

### Task 4: Synchronize operational documentation

**Files:**
- Modify: `agents/defender/README.md:73`
- Modify: `agents/defender/policy/README.md:16`
- Modify: `integration/defender-deploy.md:17`
- Modify: `integration/defender-deploy.md:68`
- Modify: `integration/defender-deploy.md:94`

**Interfaces:**
- Consumes: final shipped PolicyBundle state.
- Produces: deployment expectations that require `bundle_id=defender-2026-08-15-l1-ssrf-hotfix`, `drop_capable_rules=1`, and `demotions=[]`.

- [ ] **Step 1: Replace obsolete all-SHADOW descriptions**

Document that baseline `6/8082` is observed, only `sig-l1-helper-secret-001` is `ACTIVE`, the previous 11 rules remain `SHADOW`, and other `/fetch` requests still pass.

- [ ] **Step 2: Update deployment log gates**

Every startup-log check must expect:

```text
policy_source=active
bundle_id=defender-2026-08-15-l1-ssrf-hotfix
drop_capable_rules=1
demotions=[]
```

- [ ] **Step 3: Check documentation diff**

Run:

```powershell
rg -n "drop_capable_rules=0|모든 rule이 `SHADOW`|어떤 패킷도 차단" agents/defender integration/defender-deploy.md
```

Expected: no stale statement describes the shipped active bundle as zero-drop. Historical test comments that explicitly test demotion behavior may remain.

---

### Task 5: Full verification and focused commits

**Files:**
- Verify all modified files above.

**Interfaces:**
- Consumes: complete L1 hotfix change set.
- Produces: verified local `main` commits; no push.

- [ ] **Step 1: Run the full Defender suite**

Run from `agents/defender`:

```powershell
python -m unittest discover -s tests -t .
```

Expected: all tests pass with zero failures and zero errors.

- [ ] **Step 2: Run repository layout validation**

Run from the repository root:

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
```

Expected: exit code 0.

- [ ] **Step 3: Record the external skeleton check state**

No current official skeleton path was supplied for this session. Record `validate-skeleton: not run (path not provided)` in the handoff; do not guess a path or copy the skeleton into the repository. If the user supplies a confirmed path before final verification, run `scripts/validate-skeleton.ps1` against that exact path.

- [ ] **Step 4: Verify Git scope**

Run:

```powershell
git diff --check
git status --short --branch
```

Expected: only planned tracked files are modified; existing user-owned untracked documents remain untouched; `captures/` does not appear.

- [ ] **Step 5: Commit implementation and documentation**

Stage only the planned files and commit with English messages:

```powershell
git add agents/defender/tests/test_l1_ssrf_policy.py agents/defender/tests/test_policy_audit.py agents/defender/tests/test_timing.py agents/defender/policy/active.json
git commit -m "fix(defender): block observed L1 SSRF target"

git add agents/defender/README.md agents/defender/policy/README.md integration/defender-deploy.md
git commit -m "docs: update defender active policy runbook"
```

Do not push `main`.
