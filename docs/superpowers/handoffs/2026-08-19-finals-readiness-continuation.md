# DAH 2026 본선 준비 후속 작업 인계

사용자가 다음 세션에서 **“이어서 진행해줘”**라고 말하면 이 문서를 기준으로 아래
`재개 순서`부터 계속한다. 별도 PR은 만들지 않고, 현재 단기 브랜치에서 자체 검증 후
commit·push한다.

현재 요청 범위는 **L4만이 아니라 L1~L4 전체**다. 모든 SHADOW 규칙을 일괄 ACTIVE로
바꾸는 것이 아니라, 레이어별 실제 positive·normal negative·SLA·Broker E2E·두 리뷰를 통과한
규칙만 개별 승격한다.

## 재개 기준점

- 브랜치: `fix/finals-multiflag-l4-readiness`
- 이 인계 문서 갱신 직전 commit: `dfb94c0` (`docs: define all-layer promotion evidence gate`)
- 원격: `origin/fix/finals-multiflag-l4-readiness`
- 작업 방식: `main` 직접 push 금지, PR 생성 금지, 검증된 단기 브랜치만 push

관련 완료 commit:

- `fa1cfe7bc504d11d96d863f31b58300cdcb940fd` — `feat: harden finals agents and replay validation`
- `a307af07806bf0cf435df4a7978a3f0cded578aa` — `docs: refresh macOS finals verification`
- `a585f918c93977713ac7af56b20c4a974a7e37be` — `feat: align finals LLM and broker verification`
- `d1107ca4ac5a40f53669825fe69862d49687461a` — `fix: bind L4 behavior to observed interfaces`
- `dfb94c0` — `docs: define all-layer promotion evidence gate`

### 현재 요청의 적용 결과

- 메타 프롬프트와 자기 적용 결과:
  `docs/superpowers/specs/2026-08-19-all-layer-promotion-meta-prompt.md`
- L1 / TCP 8082: 검증된 규칙 3개 ACTIVE
- L2 / TCP 8083: 검증된 규칙 4개 ACTIVE
- L3 / TCP 8084: 검증된 규칙 2개 ACTIVE
- L4 / UGV: 실제 PCAP·port·route·normal traffic이 없어 ACTIVE 0, observation-only
- 광범위 휴리스틱 13개: 특정 공격 형태와 정상 범위가 충분히 좁지 않아 SHADOW 유지
- `test_shipped_active_rules_are_evidence_scoped_by_observed_layer`가 ACTIVE 규칙의 실제 포트,
  evidence, positive·negative·SLA fixture, owner·lead review와 `3/4/2` 분포를 고정한다.

현재 목표는 다음 두 입력이 없어 `blocked`다.

1. 기대 SHA-256
   `FFE8E6BEECB628F93F20A9F5D0F41203CADBF28EE7E56C9A91FDAB87A1655A5F`와 일치하는
   `DAH2026_본선운영세칙.pdf` 원본
2. 실제 L4 protocol·port·route와 정상/공격 traffic을 증명할 PCAP·로그·SLA 자료

원본 운영세칙을 찾기 위해 로컬 예상 보관소·다운로드·휴지통·클라우드 캐시를 해시/크기로
확인했지만 현재 시스템에는 없었다. 체크인된 조항 매핑을 원본을 다시 읽은 것으로 대체하지 않는다.

## 완료된 검증

### CI와 회귀 검사

- GitHub Actions run: <https://github.com/mamekuma-sys/Aegis.D4H-DAH2026/actions/runs/32162033556>
- 5개 job 전부 통과: `portable-foundation`, `repository-foundation`,
  `defender-tests`, `attacker-tests`, `linux-amd64-images`
- Attacker: 226 tests 통과
- Defender: 338 tests 통과, macOS에서 Linux 전용 `AF_UNIX/SOCK_SEQPACKET`
  2건만 의도대로 skip
- layout, shell entrypoint, image build contract 통과

### 104개 리허설 PCAP replay

- HTTP request 79,474개
- exploit 형태 14,407/14,407 차단
- packet drop 14,496개 중 local complete header가 없는 drop 89개
- other 65,046개 통과, coalesced 21개, unexpected drop 0개
- flag-linked 2,121/2,133 차단

### 공식 Broker x86-64 실기

- 65초 연결, session 1, heartbeat 65, `PACKET` 116
- `ACCEPT` 80 / `DROP` 36
- hot path p95 / p99 / max: 6.21 / 7.19 / 7.97ms
- verdict E2E p50: 3.05ms
- verdict E2E p95 / p99 / max: 9.41 / 13.41 / 14.12ms
- 300ms 초과: 0
- 정상 외부 fetch는 표적에 도달했다.
- ACTIVE L2 loopback-secret 요청 3건은 모두 timeout이 발생했고 표적 로그가 없었다.

### 공식 skeleton 동일성

- 공식 ZIP: `C7C67CFB10CF6D1FA0997D19EAF1DF0D7347E2C66E4F417637D866B6CCA6DF2C`
- `deploy/` tree: `8B7552FB285C3DBB75285BB083F09A5B72322B867F2472A873C2C738C20C73CE`
- agent guide: `8E7AC90ABB3186DEC73DC0AAF556F21B0A96E18F2532CFF59CB8D7A31FE9BCDB`
- Compose: `5F4ABE70556E15EDCBAF9D73BBED0A38338FA55C552EFB4C515E4C2D24539B21`
- Broker: `DDA8A4C5E2678635080F377C93C6FC3FE3E7AA3448B91B0FA8E4C8564D43E857`
- hash와 mapping만 `docs/references`에 기록했으며 공식 파일은 저장소에 넣지 않았다.
- `deploy/`의 중복 팀 agent를 제외한 모든 고유 텍스트 파일을 다시 읽었다. Compose·backend·capture는
  L1~L3/TCP 8082~8084만 구성한다. Router의 기본 `LAYERS=1,2,3,4`와
  `ENTRY_L4`·`CHAL_L4` 슬롯은 확장 구조일 뿐 실제 L4 interface 증거가 아니다.

### LLM과 전체 레이어 현재 상태

- 공지된 21개 모델을 `/v1/chat/completions`로 사용하며
  `max_completion_tokens`를 전송한다.
- 팀 전체 예산은 `$1360`이지만 모델별 가격과 당일 비용 상한이 미공지이므로
  `price_schedule`은 `null` 상태다.
- L1~L3는 실제 104개 PCAP과 공식 Broker 실기를 통과한 ACTIVE 9개를 유지한다.
- L4는 관측 가능한 protocol·port·route 증거가 아직 없다. 공격자는 응답 기반 발견만,
  방어자는 observation-only만 유지한다. 데모 L4 가정이나 합성 fixture만으로 exploit 또는
  차단 rule을 만들지 않는다.

## macOS 실행 환경

- PowerShell 없이 실행할 수 있는 Bash 검사·빌드 script가 준비되어 있다.
- Homebrew 도구 확인값: Docker Compose 5.5.0, QEMU 11.1.0,
  `lima-additional-guestagents` 2.2.0, ripgrep 15.2.0.
- x86 검증용 Colima profile `aegis-amd64`는 삭제하지 않고 정지해 두었다.
- 시작: `colima start aegis-amd64 --activate=false`
- 확인: `docker --context colima-aegis-amd64 info --format '{{.Architecture}}'`
- 기본 Colima profile은 삭제하지 않았다.
- 공식 skeleton ZIP과 압축 해제본은 저장소 밖에 둔다. 임시 경로는 다음 세션에
  남아 있다고 가정하지 않는다.

## 재개 순서

### 1. 운영세칙 원본이 제공된 경우

1. 저장소 밖에서 SHA-256이 기대값과 일치하는지 먼저 확인한다.
2. 원본 전체를 읽고 제11·13·14·15·16·20·22·23·24조 등 현재 매핑에 사용된 조항을 재대조한다.
3. 같은 날 운영진 직접 안내와 충돌하면 최신 직접 안내를 우선하고 source inventory와 영향을 기록한다.
4. PDF·추출 텍스트·렌더링 이미지는 commit하지 않는다.

### 2. 새 L1~L4 PCAP·로그·문서가 제공된 경우

1. raw 자료는 Git 밖 또는 ignore된 `capture/`에만 둔다.
2. 파일 hash, 개수, 시각 등 민감하지 않은 inventory metadata만 기록한다.
3. parser와 replay로 protocol, port, route, request/response 구조를 먼저 증명한다.
4. 공격자는 해당 endpoint의 독립 관측에 결속된 fixture와 response-driven solver만 추가한다.
5. 방어자는 `SHADOW → evidence fixture → attacker/defender owner와 팀장 검토 → ACTIVE`
   순서를 규칙별로 지킨다. 기존 SHADOW 전체를 일괄 승격하지 않는다.
6. 기존 104개와 새 PCAP을 모두 replay하고 positive 누락 0, 독립 정상 unexpected DROP 0,
   공식 SLA 안전성을 확인한다.
7. 두 이미지를 `linux/amd64`로 build한 뒤 공식 Broker smoke test를 다시 수행한다.

### 3. 가격표·비용 상한이 공지된 경우

1. `contracts/llm/model-quotas.json`의 `price_schedule`을 공식 값으로 갱신한다.
2. `$1360` 총액에 맞춘 budget ledger와 모델별 allocation을 작성한다.
3. quota, fallback, 비용 차단 동작을 test로 고정한다.

### 4. 공식 skeleton 수정본이 제공된 경우

- organizer가 challenge dependency drift인 `ModuleNotFoundError: packaging`을 수정했는지
  확인하고 전체 demo stack을 재검증한다.
- 이를 우회하려고 공식 `deploy/challenges`를 저장소에 복사하거나 수정하지 않는다.

### 5. 후순위 유지보수

- 현재 CI는 5/5 통과 상태다. GitHub Actions Node 20 deprecation warning은 본선 기능
  검증을 방해하지 않는 범위에서 별도 정리한다.

## 재개 직후 명령

```bash
git status --short --branch
git fetch origin
git pull --ff-only origin fix/finals-multiflag-l4-readiness
bash scripts/check-layout.sh
```

공식 skeleton root가 다시 준비되었을 때만 실행한다.

```bash
bash scripts/validate-skeleton.sh <official-skeleton-root>
```

PCAP 전체 replay:

```bash
bash scripts/replay-defender-pcaps.sh capture \
  --as-of 2026-08-18T00:00:00Z \
  --require-files 104 \
  --require-drop-rules 9 \
  --min-exploit-block-rate 1.0 \
  --require-zero-unexpected-other-drops
```

회귀 검사:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=agents/attacker/src \
  python3 -m unittest discover -s agents/attacker/tests

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=agents/defender/src \
  python3 -m unittest discover -s agents/defender/tests -t agents/defender

bash scripts/tests/test-shell-entrypoints.sh
bash scripts/build-images.sh
```

## 반드시 유지할 경계

- L1~L4 어느 레이어에서도 근거 없는 동작을 만들거나 SHADOW를 일괄 승격하지 않는다.
- 사용자가 지시를 바꾸기 전에는 PR을 만들지 않는다.
- `main`에 직접 push하지 않는다.
- `.env`, credential, token, flag, PDF, PCAP, log, cache, 생성 output을 commit하지 않는다.
- 공식 skeleton과 사용자 자료를 임의로 삭제하지 않는다.
- Defender의 packet synchronous hot path에 원격 LLM 호출을 넣지 않는다.

## 다음 완료 조건

다음 세션에서 운영세칙 원본을 다시 읽고 새 입력이 실제 코드·contract·문서에 반영되며, 관련
unit test, 누적 PCAP replay, `linux/amd64` build, 공식 Broker 실기와 CI가 모두 통과해야 한다.
레이어별로 증거를 통과한 규칙만 ACTIVE여야 하며 local HEAD와 원격 branch SHA가 일치할 때만
완료로 보고한다. 충족되지 않으면 남은 blocker와 근거를 구체적으로 기록한다.

## 바로 볼 문서

- [본선 준비 검증 기록](../../reviews/2026-08-19-finals-readiness-verification.md)
- [L1~L4 적용·승격 메타 프롬프트](../specs/2026-08-19-all-layer-promotion-meta-prompt.md)
- [LLM contract](../../../contracts/llm/README.md)
- [출처 inventory](../../references/source-inventory.md)
- [저장소 안내](../../../README.md)
