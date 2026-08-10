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

저장소 기반과 담당 경계를 확정한 상태입니다. 공격 런타임과 방어 런타임은 각각 별도 설계 승인 후 구현합니다. 아직 Dockerfile이 없는 것은 누락이 아니라 의도된 설계 게이트입니다.

## 처음 시작하기

다음부터는 상위 스켈레톤 폴더가 아니라 이 저장소 폴더만 엽니다. 자세한 절차는 [`docs/development-setup.md`](docs/development-setup.md)를 확인합니다.

## 로컬 검사

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
```

외부 스켈레톤 검증 방법은 [`integration/README.md`](integration/README.md)를 따릅니다.
