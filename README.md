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

공격·방어 런타임, 독립 Dockerfile, 공식 스켈레톤 Compose override와 단위·계약 테스트가 구현되어 있습니다. 방어 정책은 TEAM1 본선 PCAP에서 직접 확인한 L1~L3 exploit 네 종류만 `ACTIVE`로 집행하고 나머지 휴리스틱은 `SHADOW`로 유지합니다. flow 재조립, 실제 Broker verdict 송신 E2E 계측과 worker watchdog은 후속 설계·검증 항목입니다.

## 처음 시작하기

다음부터는 상위 스켈레톤 폴더가 아니라 이 저장소 폴더만 엽니다. 자세한 절차는 [`docs/development-setup.md`](docs/development-setup.md)를 확인합니다.

## 로컬 검사

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
```

외부 스켈레톤 검증 방법은 [`integration/README.md`](integration/README.md)를 따릅니다.

## CI

모든 push와 pull request에서 저장소 경계와 스켈레톤 검증기 테스트를 실행합니다. 공격·방어 구현이 시작되면 각 이미지의 단위 테스트, 계약 테스트, 독립 Docker 빌드를 같은 CI에 추가합니다.

## 다음 검증 게이트

1. 외부 공식 스켈레톤에서 두 이미지를 함께 실행해 Broker 수신부터 verdict 송신까지 E2E 300ms를 계측합니다.
2. packet-local ACTIVE rule의 TCP 분할 우회를 막을 bounded flow 재조립 경계를 승인합니다.
3. 필수 worker watchdog과 attacker·image build CI를 추가합니다.

## 팀 작업 방식

| 역할 | 작업 영역 |
|---|---|
| 공격 담당자 | 공격 설계, Python 구현과 테스트 |
| 방어 담당자 | 방어 설계, Python 구현과 테스트 |
| Docker 담당자 | 공격·방어 Dockerfile, 이미지 빌드, CI와 스켈레톤 연동 |
| 팀장 이경준 | 계약, 자료 추적, PR 검증과 최종 병합 |

사람별 장기 브랜치를 만들지 않습니다. 최신 `main`에서 작업 하나당 짧은 브랜치를 만들고, 필수 검토를 거친 PR만 병합합니다. 원본 대회 자료는 Git에 넣지 않으며 [`docs/references/`](docs/references/)에서 해시와 구현 매핑을 확인합니다.
