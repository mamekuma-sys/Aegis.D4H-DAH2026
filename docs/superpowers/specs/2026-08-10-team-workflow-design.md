# Aegis.0xD4H 팀 협업 및 자료 관리 설계

## 상태

- 승인일: 2026-08-10
- 팀장: 이경준
- 구성: 공격 담당자 1명, 방어 담당자 1명, Docker 담당자 1명, 팀장 1명
- 결정: 영역별 책임제, 작업별 단기 브랜치, 팀장 승인 병합, 원본 자료와 실행 저장소 분리

## 목표

네 명이 동시에 작업하더라도 공격 전략, 방어 전략, 컨테이너 패키징과 공통 계약이 뒤섞이지 않게 한다. 모든 변경은 담당자와 검증자를 식별할 수 있어야 하며, 예선·본선 원본 자료는 보존하되 현재 실행 코드와 혼합하지 않는다.

## 채택한 협업 방식

사람별 장기 브랜치를 만들지 않는다. 모든 작업은 최신 `main`에서 시작한 짧은 기능 브랜치 하나로 진행하고, 검증된 PR을 `main`에 병합한 뒤 브랜치를 삭제한다.

이 방식을 선택한 이유는 다음과 같다.

- 각 PR의 목적과 책임자가 명확하다.
- 공격·방어·Docker 변경을 독립적으로 되돌릴 수 있다.
- 장기 브랜치와 `main` 사이의 누적 충돌을 피한다.
- 팀장이 작은 단위로 검증하고 병합할 수 있다.

다음 방식은 사용하지 않는다.

- `attacker`, `defender`, `docker`라는 사람별 장기 브랜치
- 모든 팀원이 모든 경로를 자유롭게 수정하는 방식
- 검증되지 않은 통합 브랜치에 작업을 장기간 누적하는 방식

## 역할과 파일 소유권

### 공격 담당자

주 담당 경로:

- `agents/attacker/**` 중 Python 런타임과 테스트
- `research/attack-scenarios.md`
- 공격 설계 문서

책임:

- 관측, 계획, 실행, 상태 관리와 플래그 제출 설계
- A1~A5 공격자 모델과 S1~S5 시나리오를 가설로 사용하는 전략
- Python 구현과 단위·계약 테스트
- 타임아웃, 실패, 중복 플래그와 제출 rate limit 처리
- Docker 담당자에게 실행 계약 전달

공격 담당자는 Dockerfile, 공통 계약 또는 CI를 단독 확정하지 않는다.

### 방어 담당자

주 담당 경로:

- `agents/defender/**` 중 Python 런타임과 테스트
- `research/defense-mapping.md`
- 방어 설계 문서

책임:

- Broker 연결, heartbeat, 패킷 파서와 verdict 설계
- 300ms 동기 판정 경로와 온라인 상관분석 분리
- 결정론 hot path와 비동기 AI 조언 경계
- 오탐, 파싱 실패와 가용성 저하 처리
- Python 구현, 단위·계약·성능 테스트
- Docker 담당자에게 실행 계약 전달

방어 담당자는 Dockerfile, 공통 계약 또는 CI를 단독 확정하지 않는다.

### Docker 담당자

주 담당 경로:

- `agents/attacker/Dockerfile`
- `agents/defender/Dockerfile`
- `integration/**`
- `scripts/build.ps1`
- `scripts/test.ps1`
- `scripts/run-with-skeleton.ps1`
- 이미지 빌드와 통합 관련 `.github/workflows/**`

책임:

- 공격·방어 이미지를 서로 독립적으로 빌드
- Python·운영체제 의존성과 버전 고정 검증
- entrypoint, 환경변수, 로그와 종료 동작 검증
- 공식 스켈레톤 Compose override와 smoke test
- Registry 이름, 태그와 push 절차 문서화
- 이미지 digest와 빌드 증빙 보존

Docker 담당자는 공격·방어 전략 코드를 담당자 동의 없이 수정하지 않는다. 패키징에 코드 변경이 필요하면 해당 담당자에게 변경 요청을 전달한다.

### 팀장 이경준

주 담당 경로:

- `contracts/**`
- `docs/architecture.md`
- `docs/decisions/**`
- `docs/ownership.md`
- `docs/references/**`
- 공통 CI와 최종 병합

책임:

- 요구사항, 우선순위와 완료 조건 확정
- 공격·방어·Docker PR 검증 및 병합 결정
- 운영세칙과 구현 계약의 충돌 확인
- 예선 보고서·소스와 본선 구현의 추적성 검증
- 전체 로컬 공방전과 제출 이미지 최종 승인
- 필요시 양쪽 코드를 수정하되 별도 PR과 근거를 유지

## 공동 소유 영역

### 의존성 파일

에이전트 담당자는 필요한 Python 패키지와 최소 버전을 제안한다. Docker 담당자는 이미지에서 설치 가능한 버전, 고정 방식, 크기와 빌드 재현성을 검증한다. 팀장이 최종 변경을 승인한다.

### Dockerfile

Docker 담당자가 작성한다. 해당 공격 또는 방어 담당자는 entrypoint와 런타임 의존성이 실제 코드와 맞는지 검토하고, 팀장이 최종 승인한다.

### 본선 계약

`contracts/**`의 환경변수, 플래그 제출 형식, Broker 프레임, 300ms verdict와 heartbeat 변경은 관련 담당자 전원에게 영향을 알린 후 팀장이 확정한다.

## 브랜치 규칙

브랜치는 작업 목적을 나타내며 한 사람의 영구 작업 공간이 아니다.

```text
feat/attacker-runtime-foundation
feat/attacker-scenario-planner
feat/defender-broker-protocol
feat/defender-fast-verdict
chore/docker-attacker-image
chore/docker-defender-image
chore/docker-compose-integration
docs/reference-index
fix/defender-verdict-timeout
```

작업 시작:

```powershell
git switch main
git pull --ff-only
git switch -c <작업-브랜치>
```

PR 병합 후 로컬 브랜치를 삭제한다. `main`에는 직접 커밋하거나 강제 push하지 않는다.

## PR 승인 규칙

| 변경 유형 | 작성자 | 필수 검토자 |
|---|---|---|
| 공격 Python·테스트 | 공격 담당자 | 팀장 |
| 방어 Python·테스트 | 방어 담당자 | 팀장 |
| 공격 Dockerfile | Docker 담당자 | 공격 담당자, 팀장 |
| 방어 Dockerfile | Docker 담당자 | 방어 담당자, 팀장 |
| 통합·CI | Docker 담당자 | 영향받는 담당자, 팀장 |
| 공통 계약 | 팀장 또는 제안자 | 영향받는 담당자, 팀장 |
| 원본 자료 인덱스 | 팀장 | 자료 관련 담당자 |

PR에는 다음을 포함한다.

- 변경 목적과 범위
- 관련 운영세칙 또는 설계 문서
- 실행한 테스트 명령과 결과
- Docker 또는 성능 영향
- 남아 있는 위험과 롤백 방법

## 에이전트와 Docker 간 인수인계 계약

공격·방어 담당자는 Docker 담당자에게 다음 정보를 전달한다.

- 모듈 실행 명령
- 필수·선택 환경변수
- 런타임 의존성과 최소 버전
- 단위·계약 테스트 명령
- 정상 시작 로그와 종료 코드
- 재시작 가능 여부와 상태 저장 위치
- 외부 파일, 소켓 또는 네트워크 요구사항
- 비밀값을 로그로 출력하지 않는다는 검증

Docker 담당자는 각 담당자와 팀장에게 다음 결과를 전달한다.

- 재현 가능한 이미지 빌드 명령
- 로컬 실행 명령과 필요한 환경변수
- 이미지 이름, 태그, digest와 크기
- 독립 smoke test 결과
- 공식 스켈레톤 통합 테스트 결과
- 시작 시간, 종료 동작과 주요 로그

## 원본 자료 관리

### 원본 보관

다음 자료는 필요하며 팀의 비공개 공유 저장소에 원본 그대로 보존한다.

- 예선 안내서
- Aegis.0xD4H 예선 보고서
- 본선 운영세칙과 이후 운영진 공지
- 예선 제출 소스 원본 압축본
- 운영진이 제공한 공식 스켈레톤 원본

저장소의 공개 여부와 관계없이 재배포 권한을 확인하기 전에는 원본 PDF와 운영진 배포물을 코드 저장소에 커밋하지 않는다.

### Git에 기록할 자료

`docs/references/`에는 원본 대신 다음 메타데이터와 추적 문서를 기록한다.

- `README.md`: 자료 우선순위와 사용 방법
- `source-inventory.md`: 파일명, 날짜, SHA-256, 보관 위치와 공개 가능 여부
- `rules-checklist.md`: 본선 계약과 변경 추적
- `preliminary-code-map.md`: 예선 모듈과 본선 구현의 재사용·재구현·제외 매핑

개인 PC 절대경로는 기록하지 않는다. 비공개 공유 저장소의 위치는 팀원이 접근 가능한 URL 또는 공통 식별자로 기록하되 자격증명은 저장하지 않는다.

### 예선 소스 사용

예선 소스 전체를 현재 런타임 경로에 복사하지 않는다. 원본은 비공개로 보존하고, 필요한 모듈은 담당자가 테스트와 함께 새 에이전트 경로로 이식한다. `preliminary-code-map.md`에 원본 모듈, 새 모듈, 변경 이유와 검증 상태를 기록한다.

기본 분류는 다음과 같다.

- `CommonEvent`: 방어 이벤트 어댑터 설계에 활용
- 시간창·인과관계·위험도 모듈: 온라인 처리에 맞게 재구현
- `AttackSimulationAgent`: 실제 공격 코드로 이식하지 않고 S1~S5 전략 근거로만 활용
- 합성 출력과 성능 수치: 본선 성능 증빙으로 사용하지 않음

## 작업 흐름

1. 팀장이 GitHub Issue에 목적, 담당자와 완료 조건을 기록한다.
2. 담당자가 최신 `main`에서 작업 브랜치를 만든다.
3. 설계가 필요한 변경은 설계 PR을 먼저 제출한다.
4. 담당자가 테스트 우선으로 구현하고 로컬 검증 결과를 PR에 기록한다.
5. Docker 변경이 필요하면 에이전트 PR 병합 후 별도 Docker PR을 만든다.
6. 필수 검토자가 코드·계약·테스트를 검증한다.
7. 팀장이 PR을 `main`에 병합하고 기능 브랜치를 삭제한다.
8. 통합이 가능한 시점마다 두 이미지를 공식 스켈레톤에서 함께 검증한다.

장기 통합 브랜치는 만들지 않는다. `main`은 항상 현재 검증된 기준선이어야 한다.

## 첫 작업 순서

### 공격 담당자

첫 설계 PR은 관측 입력, 상태, S1~S5 가설 선택, 도구 경계, 플래그 생명주기와 rate limit을 정의한다.

### 방어 담당자

첫 설계 PR은 패킷 가시성, Broker 프로토콜, 300ms hot path, 온라인 상관 상태, 비동기 분석과 오탐 제어를 정의한다.

### Docker 담당자

첫 설계 PR은 공격·방어 이미지의 entrypoint 계약, Python 버전, 의존성 고정, 빌드·smoke test, Compose override와 Registry 흐름을 정의한다. 실제 entrypoint가 승인되기 전에 동작하지 않는 Dockerfile을 만들지 않는다.

### 팀장

세 설계 PR의 계약 충돌을 확인하고, `docs/references/` 인덱스와 최초 Issue를 만든다. 세 설계가 승인된 뒤 구현 순서와 통합 체크포인트를 확정한다.

## 완료 조건

- 공격·방어·Docker·팀장의 경로와 검토 책임이 겹치지 않게 문서화된다.
- 작업별 브랜치와 필수 PR 검토 규칙이 문서화된다.
- 공격·방어 담당자가 Docker 담당자에게 전달할 실행 계약이 정의된다.
- 원본 자료는 비공개로 보존되고 Git에는 해시와 추적 정보만 기록된다.
- 예선 소스의 재사용·재구현·제외 기준이 명확하다.
- 다음 공격·방어·Docker 설계 PR의 범위가 명확하다.

## 후속 구현 범위

이 설계 승인 후 다음 저장소 문서를 갱신한다.

- `docs/ownership.md`
- `README.md`
- `AGENTS.md`
- `docs/references/README.md`
- `docs/references/source-inventory.md`
- `docs/references/rules-checklist.md`
- `docs/references/preliminary-code-map.md`
- `scripts/check-layout.ps1`

실제 GitHub 사용자 또는 팀 이름이 확인되기 전에는 `.github/CODEOWNERS`를 만들지 않는다.
