# Attacker

본선 공격 에이전트. 관측 → 계획 → 실행 → flag 제출의 누적 적응형 런타임.
설계 근거: `docs/superpowers/specs/2026-08-11-attacker-runtime-design.md`

TEAM1 전체 104개 PCAP에서 성공이 확인된 L1 `helper-box`·대체 IP SSRF와 config traversal,
L2 관리자 session 위조·loopback secret/registry SSRF, L3 `app_meta` SQLi와 직접 노출 route는
endpoint당 최대 20회의 zero-token fast path로 일반 정찰보다 먼저 실행합니다. Phase 4
UGV는 구체 인터페이스가 아직 관측되지 않았으므로 경로를 하드코딩하지 않습니다. root와 읽기 전용
probe 응답이 실제로 노출한 route·parameter만 bounded discovery text로 다음 결정론 공격에 전달합니다.

공식 `PORTS`에 L1~L4가 함께 들어오면 알려진 데모 포트는 `L4→L1→L2→L3` wave로 섞습니다.
새 UGV 레이어를 초반에 시작하면서도 이전 세 레이어를 모두 같은 wave에 유지합니다. 데모 포트가
아닌 경우 운영 측 입력 순서를 그대로 보존합니다.

R17 이후에는 응답 본문 전체 hash가 아니라 status 계열·route·form parameter·문서 구조·오류 표식으로
만든 구조 fingerprint를 사용해 같은 서비스 구현을 팀 간 공유합니다. 성공 playbook은 고정된 최초
요청이 아니라 실제 flag를 회수한 최신 delivery로 교체됩니다. stale evidence는 root 재관측 후 한 번
재결속하고, 실패 endpoint는 30초 cooldown 또는 새 playbook generation 전에는 반복 소모하지 않습니다.
LLM은 대표 서비스 solver에 집중하도록 Round 48회·endpoint 4 turn으로 제한하며, 완전 target encoding,
중첩 SSRF, SQL 주석·제어 공백·bracket identifier 등 R17 관측 우회는 최대 6개 bounded 후보로 실행합니다.
관측 fast path 역시 `TARGETS`를 그대로 순회하므로 특정 팀 주소를 코드에 고정하지 않습니다.

표준 라이브러리만 사용한다(런타임 외부 의존성 없음).

## 구조

```
src/aegis_attacker/
├─ config.py        # 환경변수 검증(TARGETS·PORTS·SUBMIT_*·LLM_*)
├─ models.py        # Endpoint·Observation·Profile·Hypothesis·FlagCandidate 등 타입/불변조건
├─ rate_limit.py    # 전역 토큰버킷(초당 10·버스트 20)·제출(분당 30)·429 backoff
├─ observation.py   # HTTP 관측·정규화(timeout·거부도 관측)
├─ profiles.py      # ObservedServiceProfile 분류·취약 부류 우선순위 힌트
├─ phase_policy.py  # 누적 레이어 공정 예산 배분·스케줄러
├─ planner.py       # S1~S5 증거기반 가설 선택·중단(하드코딩 순서 금지)
├─ tools.py         # allowlist 실행·범위 재검증·시그니처 회피 재인코딩
├─ flags.py         # FLAG 추출·해시 중복제거·제출·5종 결과
├─ llm_advisor.py   # LLM 조언(비실행)·라운드 예산·비밀 미노출
├─ audit.py         # 비밀 제거 구조화 로그
├─ round_report.py  # 비밀 없는 Round 요약
├─ runtime.py       # 수명주기 오케스트레이터
└─ __main__.py      # 진입점 (python -m aegis_attacker)
```

## 테스트

표준 라이브러리 `unittest` 만 사용한다(외부 설치 불필요).

```powershell
cd agents/attacker
python -m unittest discover -s tests -t .
```

## 로컬 실행 (환경변수 주입)

주소·토큰·키는 하드코딩하지 않고 환경변수로만 받는다(운영세칙 제7·16조).

```powershell
$env:TARGETS="team2.lig.internal"; $env:PORTS="8082,8083,8084,8085"
$env:SUBMIT_URL="http://backend:4100/submit"; $env:SUBMIT_TOKEN="tok-team1"
$env:LLM_BASE_URL="http://litellm.lig.internal:4000"; $env:LLM_API_KEY="<key>"
$env:PYTHONPATH="src"; python -m aegis_attacker
```

표적(TARGETS·PORTS)이 없으면 inert(fail-open, 공격 없음)로 동작한다. LLM 키가 없어도 결정론 정찰은 수행한다.
포트는 코드가 개방 여부를 추측하지 않고 운영 측 `PORTS`를 그대로 사용한다.

## 스켈레톤 데모에서 실행 (end-to-end)

`nfnetlink_queue` 지원 Linux + Docker 호스트에서:

```powershell
pwsh -File ../../integration/run-with-skeleton.ps1 -SkeletonPath <스켈레톤-루트>
```

공식 스켈레톤 파일을 수정하지 않고 `integration/compose.agents.yml`로 team1-attacker 이미지만
교체한다. 스켈레톤 compose가 주입하는 공식 변수는 TARGETS·PORTS·SUBMIT_*·LLM_BASE_URL·LLM_API_KEY 이다.

## 이미지 제출 (본선)

```
docker build -t attacker:latest agents/attacker
docker tag attacker:latest ligacr.azurecr.io/team{N}/attacker:latest
docker push ligacr.azurecr.io/team{N}/attacker:latest
```

Docker 변경은 공격 담당과 팀장 이경준 검토를 받는다(integration/README).

## 설계 게이트 (충족)

관측 입력·표적 상태·도구 실행 경계·S1~S5 가설 선택·flag 생명주기·rate limit 정책은 설계 문서에서
확정했다. 예선 `AttackSimulationAgent`(합성 이벤트 생성기)는 본선 런타임으로 복사하지 않았다.
