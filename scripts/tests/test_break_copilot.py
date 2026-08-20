from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.break_copilot.approval import ApprovalError, make_template, verify_approval
from scripts.break_copilot.evaluate import _container_replay_command, _container_unit_command, evaluate_candidate
from scripts.break_copilot.ingest import IngestError, ingest
from scripts.break_copilot.llm import LiteLLMClient, analyze_manifest, assess_readiness, completion_url
from scripts.break_copilot.patching import PatchError, apply_patch, prepare_candidate, validate_patch
from scripts.break_copilot.redaction import REDACTED, redact_text, uri_shape
from scripts.break_copilot.rubric import RubricError, assessment_template, combine_assessments


VALID_PATCH = """diff --git a/agents/defender/src/aegis_defender/rules.py b/agents/defender/src/aegis_defender/rules.py
index 1111111..2222222 100644
--- a/agents/defender/src/aegis_defender/rules.py
+++ b/agents/defender/src/aegis_defender/rules.py
@@ -1 +1,2 @@
 VALUE = 1
+SAFE_LIMIT = 2
"""


class FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class RedactionTests(unittest.TestCase):
    def test_redacts_credentials_flags_and_jwt(self) -> None:
        raw = "token=super-secret FLAG{never-store} eyJabcdefgh.abcdefgh.abcdefgh"
        redacted = redact_text(raw)
        self.assertNotIn("super-secret", redacted)
        self.assertNotIn("never-store", redacted)
        self.assertNotIn("eyJabcdefgh", redacted)
        self.assertIn(REDACTED, redacted)

    def test_uri_shape_keeps_structure_not_values(self) -> None:
        shaped = uri_shape("/api/user/123?next=http://127.0.0.1/secret&token=abcdef")
        self.assertEqual("/api/user/{num}", shaped["path_shape"])
        self.assertEqual(["next", "token"], shaped["query_keys"])
        self.assertIn("loopback_target", shaped["features"])
        self.assertIn("nested_url", shaped["features"])
        self.assertNotIn("abcdef", json.dumps(shaped))


class IngestTests(unittest.TestCase):
    def test_jsonl_is_lossy_and_secret_free(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp, tempfile.TemporaryDirectory() as artifact_temp:
            raw = Path(raw_temp) / "round.log"
            raw.write_text(
                json.dumps(
                    {
                        "timestamp": "2026-08-20T01:00:00Z",
                        "event": "request",
                        "method": "GET",
                        "url": "/secret?id=123&token=do-not-store",
                        "cookie": "session=do-not-store",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            manifest, output = ingest(
                [raw], side="defender", artifact_root=Path(artifact_temp), stability_seconds=0, run_id="test-run"
            )
            encoded = output.read_text(encoding="utf-8")
            self.assertFalse(manifest["raw_content_included"])
            self.assertNotIn(str(raw.resolve()), encoded)
            self.assertNotIn("do-not-store", encoded)
            self.assertIn("/secret", encoded)
            self.assertRegex(str(manifest["evidence"][0]["evidence_id"]), r"^E-[0-9a-f]{12}$")  # type: ignore[index]

    def test_sensitive_filename_is_not_exported(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp, tempfile.TemporaryDirectory() as artifact_temp:
            raw = Path(raw_temp) / "FLAG{filename-secret}.log"
            raw.write_text('{"event":"heartbeat"}\n', encoding="utf-8")
            _, output = ingest(
                [raw], side="defender", artifact_root=Path(artifact_temp), stability_seconds=0, run_id="name-test"
            )
            encoded = output.read_text(encoding="utf-8")
            self.assertNotIn("filename-secret", encoded)
            self.assertIn("[REDACTED].log", encoded)

    def test_run_id_cannot_escape_artifact_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp, tempfile.TemporaryDirectory() as artifact_temp:
            raw = Path(raw_temp) / "round.log"
            raw.write_text("heartbeat\n", encoding="utf-8")
            with self.assertRaises(IngestError):
                ingest(
                    [raw],
                    side="defender",
                    artifact_root=Path(artifact_temp),
                    stability_seconds=0,
                    run_id="../escape",
                )

    def test_classic_pcap_metadata_without_payload_export(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp, tempfile.TemporaryDirectory() as artifact_temp:
            raw = Path(raw_temp) / "one.pcap"
            global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiiii", 2, 4, 0, 0, 65535, 1)
            payload = b"secret-payload-that-must-not-be-exported"
            packet = struct.pack("<IIII", 10, 500_000, len(payload), len(payload)) + payload
            raw.write_bytes(global_header + packet)
            manifest, output = ingest(
                [raw], side="defender", artifact_root=Path(artifact_temp), stability_seconds=0, run_id="pcap-test"
            )
            encoded = output.read_text(encoding="utf-8")
            self.assertNotIn("secret-payload", encoded)
            summary = manifest["evidence"][0]["summary"]  # type: ignore[index]
            self.assertEqual(1, summary["packet_count"])  # type: ignore[index]


class LLMTests(unittest.TestCase):
    def test_completion_url_normalization(self) -> None:
        self.assertEqual("https://proxy.example/v1/chat/completions", completion_url("https://proxy.example"))
        self.assertEqual("https://proxy.example/v1/chat/completions", completion_url("https://proxy.example/v1"))

    def test_analysis_uses_json_contract_and_does_not_put_key_in_body(self) -> None:
        captured: dict[str, object] = {}
        analysis = {
            "schema_version": 1,
            "side": "defender",
            "summary": "bounded finding",
            "findings": [{"id": "F-1", "claim": "x", "evidence_ids": ["E-123"], "confidence": "low", "falsification_test": "replay"}],
            "target_files": ["agents/defender/src/aegis_defender/rules.py"],
            "proposed_tests": ["unit"],
            "risks": [],
            "unknowns": ["official mapping"],
        }

        def opener(request: object, timeout: float) -> FakeResponse:
            captured["body"] = request.data  # type: ignore[attr-defined]
            captured["authorization"] = request.headers["Authorization"]  # type: ignore[attr-defined]
            captured["timeout"] = timeout
            return FakeResponse({"choices": [{"message": {"content": json.dumps(analysis)}}], "usage": {"total_tokens": 9}})

        client = LiteLLMClient(
            base_url="https://proxy.example",
            api_key="key-must-stay-in-header",
            allowed_models={"gpt-5.6-sol"},
            opener=opener,
        )
        manifest = {"schema_version": 1, "run_id": "r", "side": "defender", "raw_content_included": False, "evidence": []}
        result, usage = analyze_manifest(client, manifest)
        self.assertEqual("defender", result["side"])
        self.assertEqual(9, usage["total_tokens"])
        self.assertNotIn(b"key-must-stay-in-header", captured["body"])
        self.assertEqual("Bearer key-must-stay-in-header", captured["authorization"])

    def test_readiness_assessment_is_schema_checked_and_commit_bound(self) -> None:
        output = assessment("ai")

        def opener(_request: object, timeout: float) -> FakeResponse:
            self.assertGreater(timeout, 0)
            return FakeResponse({"choices": [{"message": {"content": json.dumps(output)}}], "usage": {}})

        client = LiteLLMClient(
            base_url="https://proxy.example",
            api_key="test-key",
            allowed_models={"gpt-5.6-sol"},
            opener=opener,
        )
        result, _ = assess_readiness(
            client,
            candidate_id="candidate-1",
            side="defender",
            patch=VALID_PATCH,
            evaluation={"status": "PASS"},
            manifest={"raw_content_included": False},
            scrimmage=None,
        )
        self.assertEqual("ai", result["evaluator"])


class PatchTests(unittest.TestCase):
    def test_accepts_one_side_python_patch(self) -> None:
        report = validate_patch(VALID_PATCH, side="defender")
        self.assertEqual(("agents/defender/src/aegis_defender/rules.py",), report.files)
        self.assertEqual(1, report.added_lines)

    def test_rejects_other_side_and_secret(self) -> None:
        with self.assertRaises(PatchError):
            validate_patch(VALID_PATCH, side="attacker")
        secret_patch = VALID_PATCH.replace("SAFE_LIMIT = 2", "LLM_API_KEY=real-secret")
        with self.assertRaises(PatchError):
            validate_patch(secret_patch, side="defender")

    def test_rejects_mismatched_file_headers(self) -> None:
        malicious = VALID_PATCH.replace(
            "+++ b/agents/defender/src/aegis_defender/rules.py",
            "+++ b/agents/attacker/src/aegis_attacker/runtime.py",
        )
        with self.assertRaises(PatchError):
            validate_patch(malicious, side="defender")


class SandboxCommandTests(unittest.TestCase):
    def test_unit_tests_run_in_locked_offline_read_only_container(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            command = _container_unit_command(Path(temp), "defender")
            joined = " ".join(command)
            self.assertIn("--network=none", command)
            self.assertIn("--read-only", command)
            self.assertIn("--cap-drop=ALL", command)
            self.assertIn("--security-opt=no-new-privileges=true", command)
            self.assertIn("--pull=never", command)
            self.assertIn("python:3.12-slim", command)
            self.assertNotIn("LLM_API_KEY", joined)

    def test_replay_mounts_only_explicit_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = root / "candidate"
            candidate.mkdir()
            pcap = root / "input.pcap"
            pcap.write_bytes(b"fixture")
            command = _container_replay_command(candidate, [pcap])
            self.assertIn("/evidence/0", command[-1])
            self.assertTrue(any("target=/evidence/0,readonly" in item for item in command))

    def test_evaluation_records_sandbox_image_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            candidate = Path(temp)
            (candidate / ".git").mkdir()
            (candidate / "agents/defender").mkdir(parents=True)

            def runner(command: object, _cwd: Path, _timeout: int) -> subprocess.CompletedProcess[str]:
                args = list(command)  # type: ignore[arg-type]
                stdout = ""
                if args[:3] == ["git", "branch", "--show-current"]:
                    stdout = "break/test\n"
                elif args[:3] == ["git", "rev-parse", "--verify"]:
                    stdout = "a" * 40 + "\n"
                elif args[:3] == ["git", "rev-parse", "HEAD"]:
                    stdout = "b" * 40 + "\n"
                elif args[:4] == ["git", "diff", "--no-ext-diff", "--binary"]:
                    stdout = VALID_PATCH
                elif args[:3] == ["docker", "image", "inspect"]:
                    stdout = "sha256:" + "c" * 64 + "\n"
                return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

            result = evaluate_candidate(candidate, side="defender", runner=runner)
            self.assertEqual("PASS", result["status"])
            self.assertEqual("sha256:" + "c" * 64, result["sandbox_image_id"])


@unittest.skipUnless(subprocess.run(["git", "--version"], capture_output=True).returncode == 0, "git required")
class CandidateWorktreeTests(unittest.TestCase):
    def test_patch_is_applied_only_to_isolated_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            candidate = Path(temp) / "candidate"
            source = root / "agents/defender/src/aegis_defender/rules.py"
            source.parent.mkdir(parents=True)
            source.write_text("VALUE = 1\n", encoding="utf-8")
            subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Test Human"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-m", "base"], cwd=root, check=True, capture_output=True)
            prepare_candidate(root, candidate, base_ref="HEAD", branch_name="break/testcandidate")
            report = apply_patch(root, candidate, VALID_PATCH, side="defender")
            self.assertEqual(1, report.added_lines)
            self.assertEqual("VALUE = 1\n", source.read_text(encoding="utf-8"))
            self.assertIn("SAFE_LIMIT = 2", (candidate / source.relative_to(root)).read_text(encoding="utf-8"))


def assessment(evaluator: str, *, score: int = 4, missing_evidence: bool = False) -> dict[str, object]:
    evidence = [] if missing_evidence else ["T-1"]
    gate = {"status": "PASS", "evidence_ids": ["T-1"], "reason": "tested"}
    score_item = {"value": score, "evidence_ids": evidence, "reason": "tested"}
    return {
        "schema_version": 1,
        "evaluator": evaluator,
        "candidate_id": "candidate-1",
        "hard_gates": {
            "scope_rules": dict(gate),
            "evidence_traceability": dict(gate),
            "contract_preservation": dict(gate),
            "defender_safety": dict(gate),
            "isolation_reproducibility": dict(gate),
        },
        "scores": {name: dict(score_item) for name in ("evidence", "attacker", "defender", "generalization", "performance", "operations", "llm")},
        "limitations": [],
    }


class RubricTests(unittest.TestCase):
    def test_template_starts_unscored_and_not_tested(self) -> None:
        template = assessment_template(evaluator="human", candidate_id="a" * 40)
        self.assertTrue(all(item["status"] == "NOT_TESTED" for item in template["hard_gates"].values()))  # type: ignore[union-attr]
        self.assertTrue(all(item["value"] == 0 for item in template["scores"].values()))  # type: ignore[union-attr]

    def test_conservative_minimum_and_arbitration(self) -> None:
        ai = assessment("ai", score=4)
        human = assessment("human", score=2)
        result = combine_assessments(ai, human)
        self.assertEqual("NOT_READY", result.grade)
        self.assertTrue(result.arbitration_required)
        self.assertEqual(50.0, result.score)

    def test_rejects_unsupported_score_without_evidence(self) -> None:
        with self.assertRaises(RubricError):
            combine_assessments(assessment("ai", score=4, missing_evidence=True), assessment("human"))


@unittest.skipUnless(subprocess.run(["git", "--version"], capture_output=True).returncode == 0, "git required")
class ApprovalTests(unittest.TestCase):
    def test_approval_is_bound_to_clean_commit_and_evaluation_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            candidate = Path(temp) / "candidate"
            candidate.mkdir()
            subprocess.run(["git", "init", "-b", "break/test-candidate"], cwd=candidate, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=candidate, check=True)
            subprocess.run(["git", "config", "user.name", "Test Human"], cwd=candidate, check=True)
            (candidate / "file.txt").write_text("safe", encoding="utf-8")
            subprocess.run(["git", "add", "file.txt"], cwd=candidate, check=True)
            subprocess.run(["git", "commit", "-m", "test candidate"], cwd=candidate, check=True, capture_output=True)
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=candidate, check=True, capture_output=True, text=True).stdout.strip()
            evaluation_path = Path(temp) / "evaluation.json"
            evaluation_path.write_text(json.dumps({"candidate_commit": commit, "side": "defender", "status": "PASS"}), encoding="utf-8")
            rubric_path = Path(temp) / "rubric.json"
            rubric_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "candidate_id": commit,
                        "grade": "READY",
                        "hard_gates_passed": True,
                        "arbitration_required": [],
                        "ai_assessment_sha256": "a" * 64,
                        "human_assessment_sha256": "b" * 64,
                    }
                ),
                encoding="utf-8",
            )
            template = make_template(
                candidate,
                evaluation_path,
                rubric_path,
                side="defender",
                agent_owner="Kim",
                team_lead="Lee",
                docker_owner="Park",
            )
            template["decision"] = "APPROVE"
            for review in template["reviews"]:
                review["decision"] = "APPROVE"
            approval_path = Path(temp) / "approval.json"
            approval_path.write_text(json.dumps(template), encoding="utf-8")
            result = verify_approval(candidate, evaluation_path, rubric_path, approval_path, side="defender")
            self.assertTrue(result["approved"])
            evaluation_path.write_text("{}", encoding="utf-8")
            with self.assertRaises(ApprovalError):
                verify_approval(candidate, evaluation_path, rubric_path, approval_path, side="defender")


if __name__ == "__main__":
    unittest.main()
