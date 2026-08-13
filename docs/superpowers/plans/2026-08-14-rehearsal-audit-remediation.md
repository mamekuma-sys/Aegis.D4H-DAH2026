# DAH 2026 Rehearsal Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 리허설 감사에서 재현된 공격 중복 제출과 defender 관측·복구 간극을 제거하고, 현재 commit의 두 Docker 이미지를 공식 스켈레톤에서 증거 기반으로 재검증한다.

**Architecture:** attacker는 공식 20분 Round와 4초 scan cycle을 분리해 Round state를 보존한다. defender는 물리 송신 결과 callback, bounded async TCP reassembly snapshot, 필수 worker watchdog을 기존 단일 writer·immutable snapshot 구조에 추가한다. CI와 runbook은 같은 검증을 재현 가능하게 만든다.

**Tech Stack:** Python 3.12 standard library, `unittest`, PowerShell 7, Docker/Compose, GitHub Actions.

## Global Constraints

- 공격·방어 전략을 새로 만들지 않는다.
- defender per-packet verdict path에서 원격 LLM을 호출하지 않는다.
- 정상 baseline 없이 11개 SHADOW rule을 CANARY/ACTIVE로 승격하지 않는다.
- 공식 스켈레톤과 raw competition 자료를 저장소에 복사하지 않는다.
- `.env`, token, key, flag, PCAP, log, cache, 생성 결과를 commit하지 않는다.
- 모든 behavior 변경은 failing test를 먼저 확인한다.
- `contracts/**`는 팀장 소유이며 이번 변경에서 수정하지 않는다.

---

### Task 1: Preserve attacker Round state across scan cycles

**Files:**
- Modify: `agents/attacker/src/aegis_attacker/runtime.py`
- Modify: `agents/attacker/tests/test_runtime.py`

**Interfaces:**
- Produces: `AttackerRuntime.start_round()`, `run_cycle()`, `finish_round()`; `run_once()` remains a one-Round convenience API.
- Invariant: one `FlagStore`, secret store, budget and playbook per official Round; no plaintext survives `finish_round()`.

- [ ] **Step 1: Write failing lifecycle regressions**

```python
def test_run_forever_reuses_flag_store_across_scan_cycles(self):
    arena = FakeArena("FLAG{same_round}", "/x", "irrelevant")
    rt = make_runtime(arena)
    rt.run_forever(max_cycles=2)
    self.assertEqual(len(arena.submits), 1)

def test_separate_run_once_calls_are_separate_rounds(self):
    arena = FakeArena("FLAG{new_round}", "/x", "irrelevant")
    rt = make_runtime(arena)
    rt.run_once()
    rt.run_once()
    self.assertEqual(len(arena.submits), 2)
```

- [ ] **Step 2: Verify RED**

Run: `wsl env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_runtime.TestRuntimeResilience -v`

Expected: `run_forever(max_cycles=2)` is unsupported or submits twice.

- [ ] **Step 3: Split Round and cycle lifecycle**

Keep `_build_round()` as the single constructor, add an idempotent `_finish_round()`, move endpoint execution to `run_cycle()`, and make `run_forever(max_cycles=None)` open one Round around the loop. `run_once()` opens and closes its own Round.

- [ ] **Step 4: Verify GREEN and full attacker suite**

Run: `wsl env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -t . -v`

- [ ] **Step 5: Commit**

```powershell
git add agents/attacker/src/aegis_attacker/runtime.py agents/attacker/tests/test_runtime.py
git commit -m "fix(attacker): preserve submission state for each round"
```

### Task 2: Harden attacker target scope

**Files:**
- Modify: `agents/attacker/src/aegis_attacker/config.py`
- Modify: `agents/attacker/src/aegis_attacker/egress.py`
- Modify: `agents/attacker/tests/test_config.py`
- Modify: `agents/attacker/tests/test_egress.py`
- Modify: `agents/attacker/README.md`

**Interfaces:**
- Produces: optional `team_number: int | None`; injectable `resolver(host) -> tuple[str, ...]` in `EgressGateway`.
- Invariant: self-team target and DNS answer changes fail closed before transport invocation.

- [ ] **Step 1: Write failing self-team and DNS tests**

```python
def test_team_number_excludes_own_target(self):
    cfg = load_config({"TARGETS": "team1.lig.internal,team2.lig.internal", "PORTS": "80", "TEAM_NUMBER": "1"})
    self.assertEqual(tuple(e.host for e in cfg.endpoints()), ("team2.lig.internal",))

def test_dns_answer_change_is_rejected_before_transport(self):
    answers = iter([("10.2.0.4",), ("127.0.0.1",)])
    gateway = EgressGateway(fake, allowlists, resolver=lambda host: next(answers))
    with self.assertRaises(EgressError):
        gateway.request(Capability.ATTACK_TARGET, "GET", "http://team2.lig.internal:80/")
    self.assertEqual(fake.calls, [])
```

- [ ] **Step 2: Verify RED**

Run: `wsl env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_config tests.test_egress -v`

- [ ] **Step 3: Implement validation**

Parse `TEAM_NUMBER` only when numeric and positive, filter the exact official self hostname, reject unsafe IP classes, and compare baseline/current DNS answers through an injected resolver. Do not print addresses or resolver exceptions to logs.

- [ ] **Step 4: Verify GREEN and full attacker suite**

Run: `wsl env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -t . -v`

- [ ] **Step 5: Commit**

```powershell
git add agents/attacker
git commit -m "fix(attacker): enforce target and DNS scope"
```

### Task 3: Wire defender verdict E2E telemetry

**Files:**
- Modify: `agents/defender/src/aegis_defender/session.py`
- Modify: `agents/defender/src/aegis_defender/main.py`
- Modify: `agents/defender/src/aegis_defender/metrics.py`
- Modify: `agents/defender/tests/test_session.py`
- Modify: `agents/defender/tests/test_round_lifecycle.py`

**Interfaces:**
- Produces: `SocketWriter(..., on_result=None)` callback for every terminal `SendResult`; metric constant `L_VERDICT_E2E`.
- Invariant: callback failure cannot kill or fault a healthy socket session.

- [ ] **Step 1: Write failing callback and shutdown-summary tests**

```python
def test_writer_publishes_sent_verdict_result(self):
    results = []
    writer = SocketWriter(queue, clock=clock, on_result=results.append)
    writer.attach(transport, queue.new_session())
    # enqueue one verdict and send
    self.assertEqual(results[0].outcome, SendOutcome.SENT)

def test_shutdown_log_contains_physical_verdict_latency(self):
    self.assertEqual(shutdown[0]["verdict_end_to_end"]["count"], 1.0)
    self.assertIn("p95_us", shutdown[0]["verdict_end_to_end"])
```

- [ ] **Step 2: Verify RED**

Run: `wsl env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_session tests.test_round_lifecycle -v`

- [ ] **Step 3: Implement result publication and metrics**

Call `on_result` after queue settlement for sent, expired, timeout, error, partial and stale results. Wire it to `VerdictSender.record_result`; add `verdict_end_to_end` and outcome counts to shutdown log.

- [ ] **Step 4: Verify GREEN and full defender suite**

Run: `wsl env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -t . -v`

- [ ] **Step 5: Commit**

```powershell
git add agents/defender/src agents/defender/tests
git commit -m "feat(defender): record physical verdict latency"
```

### Task 4: Connect bounded TCP reassembly to immutable verdict snapshots

**Files:**
- Modify: `agents/defender/src/aegis_defender/packet.py`
- Modify: `agents/defender/src/aegis_defender/events.py`
- Modify: `agents/defender/src/aegis_defender/state.py`
- Modify: `agents/defender/src/aegis_defender/policy.py`
- Modify: `agents/defender/src/aegis_defender/main.py`
- Modify: `agents/defender/tests/fakes.py`
- Modify: `agents/defender/tests/test_packet.py`
- Modify: `agents/defender/tests/test_events.py`
- Modify: `agents/defender/tests/test_state.py`
- Modify: `agents/defender/tests/test_policy.py`

**Interfaces:**
- Produces: `ParsedPacket.tcp_sequence`, `CorrelationEvent.payload_fragment/tcp_sequence/stream_end`, `FlowScore.reassembled_rule_ids`.
- Consumes: precompiled payload regex rules from `CompiledPolicy`.
- Invariant: only worker-owned buffers hold fragment copies; snapshots contain logical rule IDs only; each flow max 16KB and cache max 5,000 flows.

- [ ] **Step 1: Write failing parser and bounded reassembly tests**

```python
def test_parser_exposes_tcp_sequence(self):
    parsed = parse_ip(ipv4_tcp(b"abc", sequence=0x01020304))
    self.assertEqual(parsed.tcp_sequence, 0x01020304)

def test_out_of_order_segments_match_only_after_gap_closes(self):
    builder = CorrelationBuilder(reassembly_policy=compiled)
    builder.observe(fragment(seq=4, payload=b"../etc/passwd"), 1.0)
    self.assertFalse(builder.build_snapshot(1.0).entries[key].reassembled_rule_ids)
    builder.observe(fragment(seq=0, payload=b"GET "), 1.1)
    self.assertIn("path-traversal", builder.build_snapshot(1.1).entries[key].reassembled_rule_ids)
```

- [ ] **Step 2: Verify RED**

Run: `wsl env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_packet tests.test_events tests.test_state tests.test_policy -v`

- [ ] **Step 3: Implement bounded worker reassembly**

Extend `FlowReassemblyBuffer` with sequence-aware overlap/gap handling and per-flow pending limits. Match worker-local reassembled bytes against applicable compiled regexes, publish new rule IDs immediately, and have `HotPolicy._score()` enforce the referenced rule on later packets using its existing promotion-state logic.

- [ ] **Step 4: Verify privacy and policy-state behavior**

Add assertions that raw fragment bytes never appear in snapshot/advisory output; SHADOW returns ACCEPT, CANARY follows deterministic cohort, and ACTIVE returns DROP on a reassembled hit.

- [ ] **Step 5: Verify GREEN, latency and full defender suite**

Run: `wsl env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -t . -v`

- [ ] **Step 6: Commit**

```powershell
git add agents/defender/src agents/defender/tests agents/defender/README.md
git commit -m "feat(defender): connect bounded TCP reassembly"
```

### Task 5: Detect required worker death

**Files:**
- Modify: `agents/defender/src/aegis_defender/session.py`
- Modify: `agents/defender/src/aegis_defender/main.py`
- Modify: `agents/defender/src/aegis_defender/heartbeat.py`
- Modify: `agents/defender/src/aegis_defender/state.py`
- Modify: `agents/defender/src/aegis_defender/advisory.py`
- Modify: `agents/defender/tests/test_round_lifecycle.py`
- Modify: `agents/defender/tests/test_heartbeat.py`

**Interfaces:**
- Produces: worker `is_alive()` methods; optional `BrokerSession.health_check`; `worker_failure` reason.
- Invariant: normal shutdown does not become a failure; required-worker death stops the process and returns code 1.

- [ ] **Step 1: Write failing liveness regression**

```python
def test_dead_heartbeat_worker_stops_runtime_nonzero(self):
    runtime = DefenderRuntime(config(), connect_fn=connect)
    runtime.heartbeat.is_alive = lambda: False
    self.assertEqual(runtime.run(), 1)
    self.assertEqual(runtime.session.worker_failure, "heartbeat")
```

- [ ] **Step 2: Verify RED**

Run: `wsl env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_round_lifecycle -v`

- [ ] **Step 3: Implement health polling and explicit failure**

Check required workers on each receive poll. On failure, log only worker name, set shared stop event, close the active session, and return non-zero. Keep writer/correlation exception isolation for recoverable item-level failures.

- [ ] **Step 4: Verify GREEN and full defender suite**

Run: `wsl env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -t . -v`

- [ ] **Step 5: Commit**

```powershell
git add agents/defender
git commit -m "fix(defender): fail explicitly on worker death"
```

### Task 6: Add CI, provenance and current runbooks

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `agents/attacker/Dockerfile`
- Modify: `agents/defender/Dockerfile`
- Modify: `scripts/build-images.ps1`
- Create: `scripts/verify-rehearsal.ps1`
- Create: `scripts/tests/test-verify-rehearsal.ps1`
- Modify: `README.md`
- Modify: `agents/attacker/README.md`
- Modify: `agents/defender/README.md`

**Interfaces:**
- Produces: `VCS_REF` OCI label in each image and a non-pushing preflight verifier.
- Invariant: verification refuses unknown team number/notice for external actions, never prints secret values, and does not delete volumes/images.

- [ ] **Step 1: Write failing script contract tests**

Test that the verifier has `-ConfigOnly`, `-SkipBuild`, `-DurationSeconds`, checks required external input names, uses `docker compose down` without `-v`, and never invokes push/login.

- [ ] **Step 2: Verify RED**

Run: `pwsh -NoProfile -File scripts/tests/test-verify-rehearsal.ps1`

- [ ] **Step 3: Add attacker and image CI gates**

Add an Ubuntu Python 3.12 attacker test job and a Docker Buildx job that builds both `linux/amd64` images with `VCS_REF=${{ github.sha }}` and performs inspect assertions without push.

- [ ] **Step 4: Add revision labels and verifier**

Both Dockerfiles accept `ARG VCS_REF=unknown` and set `org.opencontainers.image.revision=$VCS_REF`. `build-images.ps1` passes `git rev-parse HEAD`. The verifier validates skeleton hash, builds, inspects, runs Compose for the requested duration, gathers redacted logs and performs non-volume cleanup only when it created the stack.

- [ ] **Step 5: Update documentation**

Replace stale foundation-only README text with current agent/image state, exact test commands, SHADOW warning, team-number/Registry/rehearsal URL checklist, and the remaining actual-LLM/ACTIVE gates.

- [ ] **Step 6: Verify script tests, layout and compose contract**

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
pwsh -NoProfile -File scripts/tests/test-validate-skeleton.ps1
pwsh -NoProfile -File scripts/tests/test-compose-agents-override.ps1
pwsh -NoProfile -File scripts/tests/test-verify-rehearsal.ps1
```

- [ ] **Step 7: Commit**

```powershell
git add .github agents scripts README.md
git commit -m "ci: gate rehearsal images and preflight"
```

### Task 7: Full local and official-skeleton verification

**Files:**
- Modify only if verification exposes a covered defect; return to the matching TDD task first.

**Interfaces:**
- Consumes: official skeleton path and local Docker daemon.
- Produces: command output proving current commit compatibility; no Registry mutation.

- [ ] **Step 1: Run all stateless checks and tests**

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
pwsh -NoProfile -File scripts/tests/test-validate-skeleton.ps1
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath 'C:\Users\mamekuma\Downloads\DAH2026_스켈레톤코드'
pwsh -NoProfile -File scripts/tests/test-compose-agents-override.ps1
wsl env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s agents/attacker/tests -t agents/attacker -v
wsl env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s agents/defender/tests -t agents/defender -v
```

- [ ] **Step 2: Clean-build current commit images**

Run `scripts/build-images.ps1` with `--no-cache` semantics and verify both labels equal `git rev-parse HEAD`, platform is `linux/amd64`, defender user is `65534`, and no competition secret env names have values.

- [ ] **Step 3: Run official skeleton for at least 30 seconds**

Use `scripts/verify-rehearsal.ps1 -DurationSeconds 30` with the external skeleton path. Verify attacker endpoint enumeration/request path, defender PACKET=VERDICT, HEARTBEAT >= 1, physical E2E p50/p95/p99/max below 300ms, and timeout count zero.

- [ ] **Step 4: Verify SIGTERM and reconnect**

Stop only the created agent containers without `-v`, restart the broker through the verifier's controlled test mode, and confirm defender reconnect and clean SIGTERM. Do not delete pre-existing containers or volumes.

- [ ] **Step 5: Final diff and secret audit**

```powershell
git diff --check main...HEAD
git status --short
git diff --name-only main...HEAD
rg -n "SUBMIT_TOKEN=|LLM_API_KEY=|FLAG\{" agents scripts .github README.md
```

- [ ] **Step 6: Commit any verification-only documentation and prepare handoff**

Only commit tracked source/test/docs files. Leave `TEAM_NUMBER`, Registry token, rehearsal URL and actual accepted result explicitly blocked until organizer inputs arrive.
