# Attacker

본선 공격 에이전트. 관측 → 계획 → 실행 → flag 제출의 누적 적응형 런타임.
설계 근거: `docs/superpowers/specs/2026-08-11-attacker-runtime-design.md`

과거 TEAM1 자료에서 성공이 확인된 L1 `helper-box`·대체 IP SSRF와 config traversal,
L2 관리자 session 위조·loopback secret/registry SSRF, L3 `app_meta` SQLi와 직접 노출 route는
endpoint당 최대 20회의 zero-token fast path로 일반 정찰보다 먼저 실행합니다. Phase 4
본선 P1의 `8080`은 Open-Satellite HTTP 포털로 관측됐고, `9000`은 plaintext gRPC
`satdiag.v1.SatDiag` 서비스로 관측됐습니다. 9000에서는 `Health`로 protocol을 확인한 뒤
P1-R2에서 flag를 회수한 경로와, HTTP 팀들이 잘 안 보는 축을 앞에 둡니다:
`ExportDiagnosticBundle` command-injection(`${FLAG}`/cat/printenv/environ),
`TailDiagnosticLog(/proc/self/environ|/flag)`, `ProbeEndpoint` loopback pivot.
P2-R4에서 관측한 `printf "$FLAG"` 변형과 `/portal/feedback?service_id=...`도 bounded fast path로
실행합니다. Probe/Export가 `/svc/flag-<id>/`를 반환하면 8080을 먼저 별도 관측해 해당 endpoint의
신선한 evidence를 만든 뒤 동적 경로로 피벗합니다.
이어서 관측 필드 변형을 bounded로 시도합니다. 그 밖의 미확인 서비스는 root와 읽기 전용
probe 응답이 실제로 노출한 route·parameter만 bounded discovery text로 다음 결정론 공격에 전달합니다.
미확인 포트의 discovery는 상태·문서용 6개 GET으로 제한하고, parameter를 광고된 정확한 route에
결속합니다. traversal·파괴적 action route는 실행하지 않으며, 포트별 인터페이스와 flag 상태를 섞지
않습니다.

관측된 본선 `9000`은 gRPC `Health`를 먼저 실행합니다. 그 밖의 `PORTS`는 평문 HTTP `GET /`을 먼저 실행하고,
무응답일 때만 같은 endpoint의 HTTPS `GET /`, 다시 무응답일 때만 passive TCP banner read로
이어집니다. TCP 단계는 최대 4KiB·750ms이며 client application byte를 보내지 않습니다. 경기 대상의
self-signed TLS는 `ATTACK_TARGET`에서만 허용하고 제출·LLM 인증서 검증에는 영향을 주지 않습니다.
UDP·protocol별 command는 관측 근거 없이 생성하지 않습니다.

공식 `PORTS`에 L1~L4가 함께 들어오면 알려진 데모 포트는 `L4→L1→L2→L3` wave로 섞습니다.
새 UGV 레이어를 초반에 시작하면서도 이전 세 레이어를 모두 같은 wave에 유지합니다. 데모 포트가
아닌 경우 운영 측 입력 순서를 그대로 보존합니다.

R17 이후에는 응답 본문 전체 hash가 아니라 status 계열·route·form parameter·문서 구조·오류 표식으로
만든 구조 fingerprint를 사용해 같은 서비스 구현을 팀 간 공유합니다. 성공 playbook은 고정된 최초
요청이 아니라 실제 flag를 회수한 최신 delivery로 교체됩니다. stale evidence는 root 재관측 후 한 번
재결속하고, 실패 endpoint는 30초 cooldown 또는 새 playbook generation 전에는 반복 소모하지 않습니다.
LLM은 대표 서비스 solver에 집중하도록 Round 48회·endpoint 4 turn으로 제한하며, 완전 target encoding,
중첩 SSRF, SQL 주석·제어 공백·bracket identifier 등 R17 관측 우회는 최대 6개 bounded 후보로 실행합니다.
팀 총 LLM budget은 운영진 공지의 `$1360`을 따릅니다. 공식 가격표가 없는 상태에서 USD 비용을
추정하지 않으며, 호출당 비신뢰 관측 입력을 UTF-8 8KiB로 제한하고 호출·토큰 사용량을 기록합니다.
관측 fast path 역시 `TARGETS`를 그대로 순회하므로 특정 팀 주소를 코드에 고정하지 않습니다.

표준 라이브러리만 사용한다(런타임 외부 의존성 없음).

## 구조

```
src/aegis_attacker/
├─ config.py        # 환경변수 검증(TARGETS·PORTS·SUBMIT_*·LLM_*)
├─ models.py        # Endpoint·Observation·Profile·Hypothesis·FlagCandidate 등 타입/불변조건
├─ rate_limit.py    # 전역 토큰버킷(초당 10·버스트 20)·제출(분당 30)·429 backoff
├─ observation.py   # HTTP 관측·정규화(timeout·거부도 관측)
├─ grpc_transport.py # 본선 9000 h2c gRPC unary·protobuf 최소 전송
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

```bash
cd agents/attacker
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests -t .
```

## 로컬 실행 (환경변수 주입)

주소·토큰·키는 하드코딩하지 않고 환경변수로만 받는다(운영세칙 제7·16조).

```bash
TARGETS="team2.lig.internal" \
PORTS="8080,9000" \
SUBMIT_URL="http://backend:4100/submit" \
SUBMIT_TOKEN="<token>" \
LLM_BASE_URL="http://litellm.lig.internal:4000" \
LLM_API_KEY="<key>" \
PYTHONPATH=src python3 -m aegis_attacker
```

표적(TARGETS·PORTS)이 없으면 inert(fail-open, 공격 없음)로 동작한다. LLM 키가 없어도 결정론 정찰은 수행한다.
포트는 코드가 개방 여부를 추측하지 않고 운영 측 `PORTS`를 그대로 사용한다.

## 스켈레톤 데모에서 실행 (end-to-end)

`nfnetlink_queue` 지원 Linux + Docker 호스트에서:

```bash
bash ../../integration/run-with-skeleton.sh <스켈레톤-루트>
```

Windows에서는 기존 `run-with-skeleton.ps1`을 사용합니다.

공식 스켈레톤 파일을 수정하지 않고 `integration/compose.agents.yml`로 team1-attacker 이미지만
교체한다. 스켈레톤 compose가 주입하는 공식 변수는 TARGETS·PORTS·SUBMIT_*·LLM_BASE_URL·LLM_API_KEY 이다.

## 이미지 제출 (본선)

```bash
docker buildx build --platform linux/amd64 --load \
  -t attacker:latest agents/attacker
docker image inspect attacker:latest --format '{{.Os}}/{{.Architecture}}'
docker tag attacker:latest ligacr.azurecr.io/team{N}/attacker:latest
docker push ligacr.azurecr.io/team{N}/attacker:latest
```

호스트가 arm64여도 제출 이미지는 반드시 `linux/amd64`로 빌드하며, push 전에
`docker image inspect attacker:latest --format '{{.Os}}/{{.Architecture}}'`가
`linux/amd64`인지 확인한다.

Docker 변경은 공격 담당과 팀장 이경준 검토를 받는다(integration/README).

## 설계 게이트 (충족)

관측 입력·표적 상태·도구 실행 경계·S1~S5 가설 선택·flag 생명주기·rate limit 정책은 설계 문서에서
확정했다. 예선 `AttackSimulationAgent`(합성 이벤트 생성기)는 본선 런타임으로 복사하지 않았다.
