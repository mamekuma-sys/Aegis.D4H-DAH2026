# PR Review Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the pending rehearsal-fix PR prove commit-exact image provenance, count only real flag transports, stop scan cycles at the official Round deadline, and report the current handoff state accurately.

**Architecture:** Build both Docker contexts from one `git archive HEAD` staging tree, return an immutable submission result carrying transport-attempt evidence, and share one monotonic Round deadline between `SubmitClient` and `AttackerRuntime.run_forever()`. Update the existing handoff without implementing deferred attacker/defender strategy tasks.

**Tech Stack:** Bash 3.2-compatible shell, Git archive, Docker Buildx, Python 3.12 standard library, `unittest`, macOS zsh validation, Git/GitHub PR workflow.

## Global Constraints

- Runtime code stays under `agents/attacker`; no defender strategy code changes.
- Docker build inputs must contain only bytes tracked by the labeled `HEAD` commit.
- Do not add Python or image dependencies.
- Do not print or commit account credentials, Registry tokens, flags, API keys, logs, caches, or generated image output.
- Use monotonic time for the 20-minute Round boundary; do not cancel an endpoint request already in flight.
- Preserve `ERROR` retry behavior, terminal-state deduplication, and separate `run_once()` Round semantics.
- Run each behavior through RED, minimal GREEN, focused regression, and a separate English commit.
- PowerShell is unavailable on this Mac; run the repository checks with native zsh/`rg` equivalents.
- Do not login to or push competition Registry images in this plan.
- Do not push directly to GitHub `main`; use the short-lived branch and PR.

---

### Task 1: Build Images from the Labeled Git Tree

**Files:**
- Modify: `scripts/tests/test-build-images.sh`
- Modify: `scripts/build-images.sh`

**Interfaces:**
- Consumes: `GIT_BIN`, `DOCKER_BIN`, repository `HEAD`, and tracked `agents/attacker/**` plus `agents/defender/**`.
- Produces: temporary staged contexts at `$staging_root/agents/attacker` and `$staging_root/agents/defender`; no caller-visible artifact.
- Preserves: verification tags `aegis/{attacker,defender}:verify-$short_revision` and current inspect assertions.

- [ ] **Step 1: Add an ignored-file and archive-failure regression to the shell contract test**

Set the test revision to the real current commit so the fake Git wrapper can delegate `archive` safely:

```bash
real_git="$(command -v git)"
revision="$($real_git -C "$repo_root" rev-parse HEAD)"
ignored_marker="$repo_root/agents/attacker/src/aegis_attacker/review-secret.log"
```

Replace the existing cleanup trap with one that removes only the fixture directory and exact marker path:

```bash
cleanup() {
    rm -rf -- "$fixture_dir"
    rm -f -- "$ignored_marker"
}
trap cleanup EXIT
```

In the fake Git executable, keep the current `rev-parse` and dirty-state behavior, then delegate archive without printing binary output:

```bash
elif [[ "$*" == *" archive --format=tar "* ]]; then
    if [[ "${FAKE_ARCHIVE_FAIL:-0}" == "1" ]]; then
        exit 7
    fi
    exec "$REAL_GIT_BIN" "$@"
```

In the fake Docker build branch, resolve the final argument as `context`, reject live repository contexts, and reject the ignored marker if it appears in the staged attacker context:

```bash
context="${!#}"
case "$context" in
    "$REAL_REPO_ROOT"/agents/attacker|"$REAL_REPO_ROOT"/agents/defender)
        printf '%s\n' 'live worktree used as build context' >&2
        exit 8
        ;;
esac
if [[ "$context" == */agents/attacker && \
      -e "$context/src/aegis_attacker/review-secret.log" ]]; then
    printf '%s\n' 'ignored marker entered build context' >&2
    exit 9
fi
```

Pass `REAL_GIT_BIN` and `REAL_REPO_ROOT` from `run_build()`. Before the success case, write the marker into the live ignored path:

```bash
printf '%s\n' 'must-not-enter-image' >"$ignored_marker"
```

After the success case passes, add an archive failure case and assert that the Docker log remains empty:

```bash
if run_build FAKE_ARCHIVE_FAIL=1 >"$fixture_dir/stdout" 2>"$fixture_dir/stderr"; then
    fail 'archive failure must stop the build'
fi
[[ ! -s "$docker_log" ]] || fail 'archive failure invoked docker'
grep -F -- 'git archive extraction failed' "$fixture_dir/stderr" >/dev/null \
    || fail 'archive failure reason is missing'
```

- [ ] **Step 2: Run the contract test and verify RED**

Run: `bash scripts/tests/test-build-images.sh`

Expected: FAIL because the existing script gives fake Docker the live `agents/attacker` context, causing `live worktree used as build context`.

- [ ] **Step 3: Stage the two contexts from one Git archive**

In `scripts/build-images.sh`, after Docker availability validation and before the image tags, add:

```bash
tar_bin="${TAR_BIN:-tar}"
command -v "$tar_bin" >/dev/null 2>&1 || fail 'tar executable not found'

staging_root="$(mktemp -d "${TMPDIR:-/tmp}/aegis-image-context.XXXXXX")" \
    || fail 'temporary build context creation failed'
cleanup() {
    rm -rf -- "$staging_root"
}
trap cleanup EXIT

if ! "$git_bin" -C "$repo_root" archive --format=tar "$revision" \
        agents/attacker agents/defender \
        | "$tar_bin" -xf - -C "$staging_root"; then
    fail 'git archive extraction failed'
fi
```

Change only the two context arguments:

```bash
build_image "$attacker_image" "$staging_root/agents/attacker"
build_image "$defender_image" "$staging_root/agents/defender"
```

Keep the clean-worktree rejection because it prevents an operator from believing uncommitted intended changes were built, even though the staged contexts are commit-exact.

- [ ] **Step 4: Run the focused contract test and verify GREEN**

Run: `bash scripts/tests/test-build-images.sh`

Expected: `test-build-images.sh passed`; two fake builds use staged paths, the ignored marker is absent, and archive failure invokes no Docker command.

- [ ] **Step 5: Check shell syntax and repository cleanliness**

Run:

```bash
bash -n scripts/build-images.sh
bash -n scripts/tests/test-build-images.sh
git status --short
```

Expected: both syntax checks exit 0; only the two intended scripts and the already committed plan/spec history are present.

- [ ] **Step 6: Commit the immutable-context fix**

```bash
git add scripts/build-images.sh scripts/tests/test-build-images.sh
git commit -m "fix(build): stage images from committed tree"
```

---

### Task 2: Record Only Real Submit Transports

**Files:**
- Modify: `agents/attacker/tests/test_flags.py`
- Modify: `agents/attacker/tests/test_runtime.py`
- Modify: `agents/attacker/src/aegis_attacker/flags.py`

**Interfaces:**
- Produces: `SubmitResult(state: SubmitState, attempted: bool)` as a frozen dataclass.
- Changes: `SubmitClient.submit(flag_handle) -> SubmitResult`.
- Preserves: `FlagPipeline.process(text) -> list[tuple[str, SubmitState, bool]]`; the third field now comes directly from `SubmitResult.attempted`.
- Consumes downstream: `AttackerRuntime._process_flags()` continues to call `record_submit()` only when the third field is true.

- [ ] **Step 1: Write failing unit tests for missing configuration and attempted errors**

In `TestSubmitClient`, construct a client with an empty URL and no token handle, call `submit()`, and assert via `getattr` so the old `SubmitState` return fails by assertion rather than import error:

```python
def test_missing_submit_config_is_not_a_transport_attempt(self):
    clk = FakeClock()
    rate = RateLimiter(clock=clk, sleep=lambda dt: clk.advance(dt))
    transport = ScriptedTransport([HttpResponse(200, '{"status":"accepted"}')])
    gateway = EgressGateway(transport, ALLOW)
    store = RoundSecretStore("r1", clock=clk)
    flag_handle = store.put(KIND_FLAG, "FLAG{x}")
    result = SubmitClient(gateway, rate, "", None, store, clock=clk).submit(flag_handle)

    self.assertEqual(getattr(result, "state", result), SubmitState.ERROR)
    self.assertFalse(getattr(result, "attempted", True))
    self.assertEqual(transport.calls, [])
```

Extend `test_429_beyond_round_deadline_no_retry` to assign the result and assert `result.state == SubmitState.ERROR`, `result.attempted is True`, and one transport call.

Add a pipeline-level test using the same unconfigured client:

```python
def test_missing_submit_config_returns_unattempted_error(self):
    clk = FakeClock()
    rate = RateLimiter(clock=clk, sleep=lambda dt: clk.advance(dt))
    transport = ScriptedTransport([HttpResponse(200, '{"status":"accepted"}')])
    gateway = EgressGateway(transport, ALLOW)
    store = RoundSecretStore("r1", clock=clk)
    client = SubmitClient(gateway, rate, "", None, store, clock=clk)

    result = FlagPipeline(client, store).process("FLAG{offline}")

    self.assertEqual(result[0][1:], (SubmitState.ERROR, False))
    self.assertEqual(transport.calls, [])
```

In `TestRuntimeEndToEnd`, add the exact runtime regression:

```python
def test_missing_submit_config_does_not_increment_submit_report(self):
    cfg = AttackerConfig(
        targets=("t2.lig.internal",), ports=(8082,),
        submit_url="", submit_token="",
        llm_base_url="http://litellm:4000", llm_api_key="sk-team1",
        llm_model="gpt-4o-mini",
    )
    arena = FakeArena("FLAG{offline}", "/unused", "irrelevant")
    clk = FakeClock()
    rt = AttackerRuntime(cfg, http=arena, clock=clk,
                         sleep=lambda dt: clk.advance(dt))

    report = rt.run_once()

    self.assertEqual(report.summary()["submit_states"], {})
    self.assertEqual(arena.submits, [])
```

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```bash
cd agents/attacker
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.test_flags.TestSubmitClient.test_missing_submit_config_is_not_a_transport_attempt \
  tests.test_flags.TestPipeline.test_missing_submit_config_returns_unattempted_error \
  tests.test_runtime.TestRuntimeEndToEnd.test_missing_submit_config_does_not_increment_submit_report -v
```

Expected: FAIL because the current pipeline returns `submitted=True` for the unconfigured `ERROR` result and the runtime report contains `error: 1`.

- [ ] **Step 3: Introduce the immutable result type and propagate it**

Add the import and type near the state map in `flags.py`:

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class SubmitResult:
    state: SubmitState
    attempted: bool
```

Replace `SubmitClient.submit()` with the same retry logic wrapped in `SubmitResult`:

```python
def submit(self, flag_handle) -> SubmitResult:
    if not self._url or self._token_handle is None:
        return SubmitResult(SubmitState.ERROR, attempted=False)
    flag = self._store.resolve(flag_handle)
    token = self._store.resolve(self._token_handle)
    body = json.dumps({"flag": flag, "token": token})
    for _ in range(MAX_SUBMIT_RETRIES):
        self._rate.acquire_submit()
        resp = self._egress.request(
            Capability.SUBMIT, "POST", self._url,
            headers={"Content-Type": "application/json"}, body=body, timeout=10.0)
        if resp.status == 429:
            wait = parse_retry_after(resp.headers.get("Retry-After"))
            if wait is None:
                wait = self._backoff.next_delay()
            if self._clock() + wait > self._round_deadline:
                return SubmitResult(SubmitState.ERROR, attempted=True)
            self._sleep(wait)
            continue
        self._backoff.reset()
        return SubmitResult(self._parse_state(resp), attempted=True)
    return SubmitResult(SubmitState.ERROR, attempted=True)
```

Keep secret resolution before the retry loop so a pre-transport exception still propagates.

In `FlagPipeline.process()` replace the state-only handling with:

```python
result = self._client.submit(handle)
self.store.record(fp, result.state)
results.append((fp, result.state, result.attempted))
```

Update the existing direct `SubmitClient` assertions in `test_flags.py` to compare `.state`; add `.attempted is True` where the test exercises at least one transport call.

- [ ] **Step 4: Run focused flag and runtime tests and verify GREEN**

Run:

```bash
cd agents/attacker
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.test_flags tests.test_runtime.TestRuntimeEndToEnd -v
```

Expected: all focused tests pass; missing configuration produces no transport and no submit-report state.

- [ ] **Step 5: Run the full attacker suite**

Run:

```bash
cd agents/attacker
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests -t .
```

Expected: 167 or more tests, `OK`.

- [ ] **Step 6: Commit actual-attempt reporting**

```bash
git add agents/attacker/src/aegis_attacker/flags.py \
  agents/attacker/tests/test_flags.py agents/attacker/tests/test_runtime.py
git commit -m "fix(attacker): report only transport submissions"
```

---

### Task 3: Stop New Scan Cycles at the Round Deadline

**Files:**
- Modify: `agents/attacker/tests/test_runtime.py`
- Modify: `agents/attacker/src/aegis_attacker/runtime.py`

**Interfaces:**
- Produces: `AttackerRuntime._round_deadline: float`, initialized to `0.0` and set once per `start_round()`.
- Consumes: existing injected monotonic `clock`, `sleep`, `ROUND_DURATION`, `LOOP_SLEEP`, and optional `max_cycles`.
- Preserves: `run_once()` one-cycle semantics and caller-owned `start_round()`/`finish_round()` behavior.

- [ ] **Step 1: Write a failing deadline-loop regression**

Import `patch` from `unittest.mock`. Add a minimal loop test double inside the test method or test class:

```python
class CycleOnlyRuntime(AttackerRuntime):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cycles = 0

    def run_cycle(self):
        if not self._round_active:
            raise RuntimeError("inactive Round")
        self.cycles += 1
        return self._report
```

Add the regression:

```python
def test_run_forever_stops_at_round_deadline_and_wipes_secrets(self):
    clk = FakeClock()
    sleeps = []

    def sleep(dt):
        sleeps.append(dt)
        clk.advance(dt)

    with patch("aegis_attacker.runtime.ROUND_DURATION", 5.0):
        rt = CycleOnlyRuntime(make_cfg(), http=FakeArena("b", "/x", "FLAG{x}"),
                              clock=clk, sleep=sleep)
        rt.run_forever(max_cycles=3)

    self.assertEqual(rt.cycles, 2)
    self.assertEqual(sleeps, [4.0, 1.0])
    self.assertEqual(clk.t, 5.0)
    self.assertEqual(rt._secret_store.secrets_snapshot(), set())
```

- [ ] **Step 2: Run the deadline test and verify RED**

Run:

```bash
cd agents/attacker
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.test_runtime.TestRuntimeResilience.test_run_forever_stops_at_round_deadline_and_wipes_secrets -v
```

Expected: FAIL because the old loop runs all three cycles and sleeps `[4.0, 4.0]`, while the regression expects two cycles and deadline-capped sleeps `[4.0, 1.0]`.

- [ ] **Step 3: Store and enforce one Round deadline**

Initialize in `__init__`:

```python
self._round_deadline = 0.0
```

In `_build_round()`:

```python
now = self.clock()
self._round_deadline = now + ROUND_DURATION
```

Pass `round_deadline=self._round_deadline` to `SubmitClient`. Replace the `run_forever()` loop and sleep condition with:

```python
while ((max_cycles is None or cycles < max_cycles)
       and self.clock() < self._round_deadline):
    report = self.run_cycle()
    self.audit.log("round-summary", **report.summary())
    cycles += 1

    cycles_remaining = max_cycles is None or cycles < max_cycles
    remaining = self._round_deadline - self.clock()
    if cycles_remaining and remaining > 0:
        self.sleep(min(LOOP_SLEEP, remaining))
```

Do not reset `_round_deadline` before `finish_round()` completes; the completed Round remains inspectable in tests while all secret values are expired.

- [ ] **Step 4: Run focused lifecycle tests and verify GREEN**

Run:

```bash
cd agents/attacker
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.test_runtime.TestRuntimeResilience tests.test_runtime.TestRuntimeInert -v
```

Expected: deadline regression returns at fake time 5.0, existing two-cycle dedup remains one submit, and inert mode returns immediately.

- [ ] **Step 5: Run the full attacker suite**

Run:

```bash
cd agents/attacker
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests -t .
```

Expected: all tests pass with no hang.

- [ ] **Step 6: Commit the Round boundary**

```bash
git add agents/attacker/src/aegis_attacker/runtime.py agents/attacker/tests/test_runtime.py
git commit -m "fix(attacker): stop cycles at round deadline"
```

---

### Task 4: Replace the Stale Handoff State

**Files:**
- Modify: `docs/superpowers/handoffs/2026-08-14-rehearsal-audit-remediation.md`

**Interfaces:**
- Consumes: completed commit history and same-day organizer notice.
- Produces: a credential-free current status document separating completed PR scope from deferred rehearsal work.

- [ ] **Step 1: Rewrite the current-state sections**

Replace the initial “production code unchanged” state with these facts:

```markdown
- 팀 번호: 1
- 리허설 URL: https://rade.dev.ctf-zone.com/
- 계정·비밀번호·Registry token: 저장소에 기록하지 않음
- 현재 PR: Round FlagStore persistence, cross-cycle/concurrent dedup,
  actual transport reporting, immutable image context와 revision verification
- deferred: Registry 인증·push 방식, pull 마감, 공식 스켈레톤 30초 동시 실행
```

Move the old WSL baseline and “문서 단계” statements under an explicitly historical heading or remove them when they no longer help the current handoff. Keep Tasks 2~5 and the unimplemented portion of Task 6 as deferred; do not mark the full audit plan complete.

Record `f07f6b25877de8ae38e12380d8f6eb020dce692c` as the last image SHA already clean-built before this review remediation and state that the new final-SHA build is pending Task 5. A tracked document cannot contain the SHA of the commit that contains itself, so the final remediation SHA belongs in the PR verification record after the handoff commit. Do not include an email, password, token, local absolute path, raw notice, or image build log.

- [ ] **Step 2: Run static handoff assertions**

Run:

```bash
rg -n '팀 번호: 1|https://rade.dev.ctf-zone.com/|deferred|미완료' \
  docs/superpowers/handoffs/2026-08-14-rehearsal-audit-remediation.md
! rg -n 'production code와 test code는 변경하지 않았다|현재 작업은 문서 단계까지만 완료' \
  docs/superpowers/handoffs/2026-08-14-rehearsal-audit-remediation.md
git diff --check
```

Expected: current facts and deferred work are found; both stale claims are absent; diff check exits 0.

- [ ] **Step 3: Commit the handoff correction**

```bash
git add docs/superpowers/handoffs/2026-08-14-rehearsal-audit-remediation.md
git commit -m "docs: update rehearsal remediation handoff"
```

---

### Task 5: Verify the Final SHA, Re-review, and Merge Through PR

**Files:**
- Verify only: all files changed since `origin/main`
- External action: GitHub branch, PR, checks, and merge

**Interfaces:**
- Consumes: clean feature branch with Tasks 1~4 committed and existing owner/team-lead approvals.
- Produces: passing final SHA, updated remote feature branch, reviewed PR, merged remote `main`, and a synchronized clean local `main`.

- [ ] **Step 1: Run the complete Python and shell suites**

Run:

```bash
cd agents/attacker
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests -t .

cd ../defender
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests -t .

cd ../..
bash scripts/tests/test-build-images.sh
bash -n scripts/build-images.sh scripts/tests/test-build-images.sh
git diff --check origin/main...HEAD
git status --short --branch
```

Expected: attacker 167 or more and defender 275 tests pass, shell contract passes, syntax and diff checks exit 0, worktree is clean.

- [ ] **Step 2: Run macOS-native layout, skeleton, and Compose contract equivalents**

Run the native layout equivalent from the repository root:

```zsh
set -euo pipefail
required=(
  .gitattributes .gitignore .env.example .github/workflows/ci.yml
  .github/pull_request_template.md AGENTS.md CONTRIBUTING.md README.md
  agents/README.md agents/attacker/README.md
  agents/attacker/src/aegis_attacker/.gitkeep agents/attacker/tests/.gitkeep
  agents/defender/README.md agents/defender/src/aegis_defender/.gitkeep
  agents/defender/tests/.gitkeep contracts/README.md contracts/attacker/README.md
  contracts/defender/README.md contracts/fixtures/README.md docs/architecture.md
  docs/development-setup.md docs/decisions/0001-external-skeleton.md
  docs/meeting-notes/.gitkeep docs/ownership.md docs/references/README.md
  docs/references/source-inventory.md docs/references/rules-checklist.md
  docs/references/preliminary-code-map.md integration/README.md
  research/preliminary-strategy.md research/attack-scenarios.md
  research/defense-mapping.md scripts/validate-skeleton.ps1
  scripts/tests/test-validate-skeleton.ps1
  scripts/tests/test-compose-agents-override.ps1 integration/compose.agents.yml
  integration/run-with-skeleton.ps1 integration/attacker-deploy.md
  integration/defender-deploy.md
)
for rel in "${required[@]}"; do [[ -f "$rel" ]] || exit 1; done
for rel in deploy tmp output __pycache__; do [[ ! -e "$rel" ]] || exit 1; done
if git ls-files | rg -i '(\.pdf|\.zip|\.tar|\.gz|\.pcap|\.pcapng)$|(^|/)(DAH2026_본선_당일_진행_안내\.md|DAH2026_스켈레톤코드_상세_설명\.md)$'; then
  exit 1
fi
portable=()
while IFS= read -r rel; do
  case "$rel" in
    *.md|*.ps1|*.py|*.yml|*.yaml|*.json|*.toml|*.txt|*.example) portable+=("$rel") ;;
  esac
done < <(git ls-files)
if (( ${#portable[@]} > 0 )) && rg -l '(?i)[A-Z]:\\Users\\[^\\\r\n]+\\|/Users/[^/[:space:]]+/|/home/[^/[:space:]]+/' "${portable[@]}"; then
  exit 1
fi
print 'Repository layout check passed (macOS equivalent).'
```

Run the skeleton validator contract equivalent:

```zsh
set -euo pipefail
validator=scripts/validate-skeleton.ps1
[[ -f "$validator" ]]
for rel in deploy/docker-compose.yml deploy/docs/agent-guide.md \
  deploy/agents/team1/attacker/Dockerfile \
  deploy/agents/team1/defender/Dockerfile deploy/router/broker; do
  rg -F -q "'$rel'" "$validator"
done
rg -F -q 'Validated DAH skeleton' "$validator"
rg -F -q 'Invalid DAH skeleton. Missing:' "$validator"
print 'Skeleton validator contract passed (macOS equivalent).'
```

Run the 29-case Compose/runbook equivalent:

```zsh
set -euo pipefail
override=integration/compose.agents.yml
runner=integration/run-with-skeleton.ps1
attacker=integration/attacker-deploy.md
defender=integration/defender-deploy.md
dockerfile=agents/defender/Dockerfile
for rel in "$override" "$runner" "$attacker" "$defender" "$dockerfile"; do
  [[ -f "$rel" ]]
done
if rg -q '^\s*context:\s*\.\./agents/(attacker|defender)\s*$' "$override"; then exit 1; fi
for pattern in AEGIS_ATTACKER_CONTEXT AEGIS_DEFENDER_CONTEXT team1-defender:; do
  rg -F -q -- "$pattern" "$override"
done
for pattern in AEGIS_ATTACKER_CONTEXT AEGIS_DEFENDER_CONTEXT \
  'config --format json' ConfigOnly LogsDefender ReapplyAgents --no-deps --no-build \
  --force-recreate team1-attacker team1-defender Config.Image \
  'Run -ReapplyAgents after /control/start'; do
  rg -F -q -- "$pattern" "$runner"
done
if rg -q "'down',\s*'-v'|down -v" "$runner"; then exit 1; fi
if rg -q '^COPY policy /app/policy\s*$' "$dockerfile"; then exit 1; fi
rg -q '^COPY policy /policy\s*$' "$dockerfile"
if rg -q '2026-08-13' "$attacker"; then exit 1; fi
for pattern in 'python -m unittest discover' check-layout.ps1 validate-skeleton.ps1 \
  ConfigOnly LLM_MODEL gpt-4o-mini "throw 'docker build failed'" \
  "throw 'docker push failed'" ReapplyAgents "throw 'reapply team agent images failed'"; do
  rg -F -q -- "$pattern" "$attacker"
done
if rg -q 'LLM_MODEL\(gpt-4o-mini\)' "$attacker"; then exit 1; fi
for pattern in 'python -m unittest discover' check-layout.ps1 validate-skeleton.ps1 \
  ConfigOnly policy_source=active drop_capable_rules=0 'COPY policy /policy' \
  "throw 'docker build failed'" "throw 'docker push failed'" \
  'team{N}/defender:latest' ReapplyAgents "throw 'reapply team agent images failed'"; do
  rg -F -q -- "$pattern" "$defender"
done
print 'Agent Compose override tests passed: 29 cases (macOS equivalent).'
```

Expected:

```text
Repository layout check passed (macOS equivalent).
Skeleton validator contract passed (macOS equivalent).
Agent Compose override tests passed: 29 cases (macOS equivalent).
```

- [ ] **Step 3: Clean-build and inspect both final-SHA images**

Ensure Colima is running, then execute:

```bash
colima start
bash scripts/build-images.sh
```

Expected: two `--no-cache --platform linux/amd64` builds succeed from staged Git contexts. Both verification lines show the full current `git rev-parse HEAD`; attacker CMD and default user, defender CMD and user `65534`, and empty competition-secret environment values pass.

Record image IDs and revision labels in the PR description, not in tracked files. Stop Colima after all Docker checks; do not delete its images or volumes.

- [ ] **Step 4: Request a fresh independent code review**

Use `superpowers:requesting-code-review` with:

```text
Base: aa1c4b57b885a9bfa4fbd6921ac6a88a4f67e2ea
Head: output of `git rev-parse HEAD`
Requirements: original rehearsal remediation design plus
docs/superpowers/specs/2026-08-14-pr-review-remediation-design.md
```

Expected: no Critical or Important findings. Fix any such finding with a new RED/GREEN cycle before continuing.

- [ ] **Step 5: Push the reviewed branch without force**

```bash
git push origin fix/rehearsal-audit-findings
```

Expected: remote branch fast-forwards to the reviewed final SHA.

- [ ] **Step 6: Create or update the GitHub PR**

Use the existing authenticated GitHub browser session because `gh` is not authenticated. Target `main` from `fix/rehearsal-audit-findings`. Include:

- current scope and the four review remediations;
- exact unit/contract counts;
- final SHA and two image IDs/revision labels;
- owner, Docker owner, and team-lead approvals;
- deferred official-skeleton and Registry rehearsal steps;
- rollback by reverting the PR.

Expected: the PR shows the final commit range, no secrets, and mergeability against current `main`.

- [ ] **Step 7: Wait for required GitHub checks and merge the approved PR**

Do not bypass a failed check or branch protection. If `origin/main` moved, fetch and merge/rebase only through a new reviewed branch commit; never force-push. Merge once required checks are green and the recorded approvals remain valid.

Expected: GitHub reports the PR merged into `main`.

- [ ] **Step 8: Synchronize local main and clean the short-lived branch**

```bash
git switch main
git pull --ff-only
git branch -d fix/rehearsal-audit-findings
git status --short --branch
git rev-parse HEAD
```

Expected: local `main` equals `origin/main`, worktree is clean, and the local feature branch is gone. Delete the remote branch through the merged PR cleanup control only after confirming the PR is merged.

- [ ] **Step 9: Report the exact terminal state**

Report the PR URL, merge commit or fast-forward SHA, test counts, image IDs/revision, clean Git status, and only these remaining rehearsal gates:

- Registry authentication/push and pull deadline;
- official skeleton attacker/defender 30-second co-run;
- PACKET/VERDICT/HEARTBEAT and reconnect observation.
