# 본선 자료 정규화 및 비공개 보관 설계

## 상태

- 승인일: 2026-08-10
- 작업 브랜치: `docs/finals-source-alignment`
- 소유자: 팀장 이경준
- 목적: 본선 자료에서 확인한 규칙과 실행 계약만 저장소 문서에 반영하고, 원본 5개 파일은 Git 밖에서 보존한다.

## 결정

이 변경은 `main`이나 공격·방어·Docker 설계 브랜치에 직접 작성하지 않는다. 팀장 소유의 단기 브랜치에서 공통 사실을 정규화하고 PR로 `main`에 병합한 뒤 브랜치를 삭제한다. 세 담당자의 설계 브랜치는 갱신된 `main`을 기준으로 자신의 설계를 작성한다.

별도 linked worktree는 만들지 않는다. 현재 checkout에서 단기 브랜치로 전환해 작업하며, 추적 파일은 정확한 경로만 stage한다.

## 자료 분류와 우선순위

| 자료 | 분류 | 사용 범위 |
|---|---|---|
| `DAH2026_본선운영세칙.pdf` | 본선 공식 원본 | 네트워크, 제출, 실행, 채점, 금지행위의 기준 |
| `DAH 예선_안내서.pdf` | 예선 공식 원본 | 예선 목적과 제출 배경만 확인 |
| `DAH2026_예선보고서_Aegis.0xD4H.pdf` | 팀 예선 제출 원본 | A1~A5, S1~S5, 상관분석 개념의 추적 근거 |
| `DAH2026_본선_당일_진행_안내.md` | 파생 팀 메모 | 운영세칙의 팀용 설명으로만 사용 |
| `DAH2026_스켈레톤코드_상세_설명.md` | 파생 팀 메모 | 실제 스켈레톤 검증 전 이해 보조 자료로만 사용 |

사실이 충돌하면 최신 운영진의 직접 안내, 본선 운영세칙, 공식 `deploy/docs/agent-guide.md`, 실제 스켈레톤, 예선 자료, 파생 팀 메모 순으로 판단한다. 여기서 운영진 직접 안내는 `FINALS-DAY-NOTE`를 뜻하지 않는다. `FINALS-DAY-NOTE`와 `SKELETON-EXPLANATION`은 공식 원본이 아닌 파생 팀 메모다.

## Git에 반영할 파일

### `.gitignore`

- PDF 전체 제외 규칙을 유지한다.
- 첨부된 파생 Markdown 2개의 정확한 파일명을 추가해 재첨부 시 실수로 stage되지 않게 한다.

### `docs/references/source-inventory.md`

- 기존 PDF 3개의 SHA-256을 유지하고 현재 첨부본과 일치함을 기록한다.
- 파생 Markdown 2개의 SHA-256, 자료 성격, Git 정책을 추가한다.
- 원본의 개인 PC 절대경로는 기록하지 않는다.

### `docs/references/rules-checklist.md`

본선 운영세칙에서 확인한 다음 제약을 추가한다.

- 공격 대상 접근은 초당 10회, 버스트 20이다.
- flag 제출은 분당 30회이며 HTTP 429를 처리한다.
- 공격자는 허용된 팀 진입점, LiteLLM, 제출 서버 외부에 접근하지 않는다.
- NAT로 인해 방어 측은 소스 IP로 공격자를 식별할 수 없다.
- 레이어 네트워크에는 30ms 지연과 0.3% 손실이 모사된다.
- 방어 에이전트 부재·사망 시 Broker는 fail-open이며, verdict 300ms 초과 시 해당 패킷은 DROP된다.
- 컨테이너와 flag는 라운드마다 초기화된다.
- 이미지는 라운드 시작 5분 전에 pull되며 pull timeout은 20분이다.
- 동점 시 LLM 토큰 비용이 사용되므로 호출 예산과 증빙을 관리한다.
- DoS, 범위 외 접근, 운영망 침범, rate limit 우회, flag 목적 밖의 파괴·변조를 금지한다.

### `contracts/attacker/README.md`

- 허용 네트워크 범위와 접근 제한을 명시한다.
- flag 상태와 분당 제출 제한, 중복 방지 요구를 명시한다.
- 라운드 단위의 임시 상태와 토큰 비용 관리 요구를 명시한다.

### `contracts/defender/README.md`

- NAT, 네트워크 지연·손실, fail-open, timeout DROP의 의미를 명시한다.
- 원시 IP 패킷만 계약된 입력이며 차량 상태·임무 의미·파라미터 해시를 가정하지 않는다고 명시한다.
- heartbeat와 verdict가 서로 막지 않아야 한다는 실행 요구를 추가한다.

### `integration/README.md`

- `FINALS-RULES` 14절에 근거해 공격·방어 이미지 이름과 `latest` 태그를 기록한다.
- `FINALS-RULES` 15절에 근거해 라운드 시작 전 pull 시각, pull timeout, 컨테이너 수명을 기록한다.
- `FINALS-RULES` 16절에 근거해 `no-new-privileges`, CPU·메모리·PID 제한, 방어 `cap-drop ALL`, 소켓 마운트와 환경변수 주입을 공식 실행 값으로 기록한다.
- `OFFICIAL-SKELETON`과 공식 agent guide는 실제 Compose·mount·주입 구현이 운영세칙과 최신 운영진 직접 안내에 맞는지 확인하는 데 사용한다.
- 실제 스켈레톤을 복사하지 않고 Compose override로 연결하는 원칙을 유지한다.

### `docs/architecture.md`

- 본선에서 관측 가능한 입력과 예선 개념의 경계를 보강한다.
- 예선의 RTL·롤백·HITL은 본선의 직접 실행 인터페이스가 아니며, 런타임에서는 `ACCEPT/DROP`과 비동기 분석으로 축소한다고 명시한다.

## Git 밖 자료 보관 구조

원본 파일은 저장소 밖의 다음 비공개 디렉터리로 이동한다.

```text
Aegis.D4H-DAH2026-private/
└─ references/
   └─ 2026-08-10/
      ├─ official/
      │  ├─ DAH 예선_안내서.pdf
      │  └─ DAH2026_본선운영세칙.pdf
      ├─ team-submission/
      │  └─ DAH2026_예선보고서_Aegis.0xD4H.pdf
      ├─ derived-notes/
      │  ├─ DAH2026_본선_당일_진행_안내.md
      │  └─ DAH2026_스켈레톤코드_상세_설명.md
      └─ MANIFEST.md
```

`MANIFEST.md`에는 논리적 분류, SHA-256, 보존 이유와 권위 수준을 기록한다. 다섯 자료는 모두 추적 근거가 있으므로 삭제하지 않는다. 저장소 루트의 원본은 이동으로 제거하며, 임시 렌더링·추출물만 삭제한다.

## 검증

완료 전 다음을 확인한다.

1. `pwsh -NoProfile -File scripts/check-layout.ps1`
2. 외부 스켈레톤 경로가 있으면 `scripts/validate-skeleton.ps1` 실행
3. `git status --short`에 원본 5개가 나타나지 않음
4. `git ls-files`에 원본 5개가 포함되지 않음
5. 비공개 보관본 5개의 SHA-256이 인벤토리·매니페스트와 일치함
6. 문서에 토큰·키·개인 절대경로가 포함되지 않음
7. 변경 diff가 문서·ignore 규칙으로만 구성됨

현재 `..\deploy` 경로에는 외부 스켈레톤이 없으므로, 이번 변경에서는 스켈레톤 검증을 실행할 수 없다. 공식 스켈레톤이 제공되면 별도 검증 결과를 남긴다.

## 비목표

- 공격·방어 Python 구현
- Dockerfile 또는 Compose 구현
- 본선 취약점 추정이나 데모 취약점 하드코딩
- 예선 synthetic 성능 수치를 본선 성능으로 주장
- 설계 브랜치 3개의 담당자 문서를 대신 완성

## 병합 이후

이 PR이 `main`에 병합되면 공격·방어·Docker 담당자는 최신 `main`을 반영하고, 각 설계 브랜치에서 본 문서의 계약을 구현 설계 입력으로 사용한다. 이 단기 브랜치는 병합 후 로컬과 원격에서 삭제한다.
