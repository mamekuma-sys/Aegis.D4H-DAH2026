# Aegis.0xD4H DAH 2026 Agents

DAH 2026 본선용 공격·방어 에이전트를 개발하는 팀 저장소입니다.

## 핵심 원칙

- 공격과 방어는 각각 독립 Docker 이미지로 빌드합니다.
- 본선 인터페이스는 개발 초기부터 계약 테스트로 고정합니다.
- 공식 스켈레톤 전체는 이 저장소에 복사하지 않고 외부 로컬 시험장으로 사용합니다.
- 예선 보고서의 전략을 기반으로 하되, 실제 본선에서 관측 가능한 입력에 맞춰 재구현합니다.

## 저장소 구조

```text
agents/
├─ attacker/          공격 담당자 작업 영역
└─ defender/          방어 담당자 작업 영역
contracts/            본선 인터페이스 계약과 고정 fixture
integration/          외부 공식 스켈레톤 연동
research/             예선 전략과 본선 구현의 연결 근거
docs/                 아키텍처, 결정 기록, 회의 기록
scripts/              공통 검증 및 실행 도구
```

## 현재 단계

공격·방어 런타임, 독립 Dockerfile, 공식 스켈레톤 Compose override와 단위·계약 테스트가 구현되어 있습니다. 공격자는 TEAM1 PCAP에서 성공이 확인된 L1~L3 형태를 zero-token fast path로 우선 실행하고, Phase 4 UGV는 실제 응답에서 발견한 route만 공격하며 L1~L4를 누적 순회합니다. 방어 정책은 같은 PCAP에서 직접 확인한 L1~L3 exploit 형태에 대응하는 9개 규칙만 `ACTIVE`로 집행하고 나머지 휴리스틱은 `SHADOW`로 유지합니다. bounded HTTP stream stitching, worker watchdog, PACKET 수신부터 실제 verdict socket 송신 완료까지의 E2E 계측이 연결되어 있습니다. Linux 계약 테스트에 더해 공식 Broker 실기에서도 65초간 heartbeat 65회, PACKET 116개, ACCEPT 80/DROP 36, verdict 송신 E2E 최대 14.12ms를 확인했습니다. 상세 증거는 [`본선 준비 검증 기록`](docs/reviews/2026-08-19-finals-readiness-verification.md)에 있습니다.

## 처음 시작하기

다음부터는 상위 스켈레톤 폴더가 아니라 이 저장소 폴더만 엽니다. 자세한 절차는 [`docs/development-setup.md`](docs/development-setup.md)를 확인합니다.

## 로컬 검사

```bash
bash scripts/check-layout.sh
bash scripts/build-images.sh
```

두 번째 명령은 Docker가 실행 중이어야 하며 깨끗한 현재 commit을 `linux/amd64`로
빌드한 뒤 revision label, CMD, 방어 이미지 비루트 사용자와 비밀 환경변수 미포함을 검사합니다.
Windows에서는 `pwsh -NoProfile -File scripts/check-layout.ps1`을 사용합니다.

Git 제외 경로 `capture/`에 리허설 PCAP이 있을 때는 다음 회귀도 실행합니다.

```bash
bash scripts/replay-defender-pcaps.sh capture \
  --as-of 2026-08-18T00:00:00Z \
  --require-files 104 \
  --require-drop-rules 9 \
  --min-exploit-block-rate 1.0 \
  --require-zero-unexpected-other-drops
```

외부 스켈레톤 검증 방법은 [`integration/README.md`](integration/README.md)를 따릅니다.

## CI

모든 push와 pull request에서 저장소 경계·스켈레톤 검증기, 공격·방어 단위 테스트와
두 독립 `linux/amd64` 이미지의 clean build·inspect 검증을 실행합니다.

## 다음 검증 게이트

1. 본선 L4 PCAP/인터페이스를 확보한 뒤 관측 fixture와 방어 rule 승격 여부를 승인합니다.
2. 공식 스켈레톤 challenge 의존성 drift가 해소된 배포본에서 공격·방어 전체 demo stack을 재확인합니다.
3. [`LLM 계약`](contracts/llm/README.md)에 당일 운영진 가격·과금 기준을 반영한 뒤
   팀 공용 `$1360` 비용 ledger와 공격·방어 배분을 확정합니다.

## 팀 작업 방식

| 역할 | 작업 영역 |
|---|---|
| 공격 담당자 | 공격 설계, Python 구현과 테스트 |
| 방어 담당자 | 방어 설계, Python 구현과 테스트 |
| Docker 담당자 | 공격·방어 Dockerfile, 이미지 빌드, CI와 스켈레톤 연동 |
| 팀장 이경준 | 계약, 자료 추적, PR 검증과 최종 병합 |

사람별 장기 브랜치를 만들지 않습니다. 최신 `main`에서 작업 하나당 짧은 브랜치를 만들고, 필수 검토를 거친 PR만 병합합니다. 원본 대회 자료는 Git에 넣지 않으며 [`docs/references/`](docs/references/)에서 해시와 구현 매핑을 확인합니다.
