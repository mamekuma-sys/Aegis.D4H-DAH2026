# 방어 에이전트 배포 런북 (handoff)

배포 담당자를 위한 운영 문서. 코드/설계 근거는 `docs/superpowers/specs/2026-08-11-defender-runtime-design.md`,
계약은 `docs/references/rules-checklist.md`·`integration/README.md`를 참조한다.

공격 이미지와 같은 스켈레톤 override를 쓰므로 라이브 스모크는 공격·방어를 함께 기동한다.
공격 전용 절차는 `integration/attacker-deploy.md`를 따른다.

## 1. 배포마다 다시 통과할 게이트

이전 날짜의 통과 기록을 재사용하지 않는다. Registry push 전에 현재 커밋에서 아래를 **다시** 실행한다.

1. 방어 에이전트 전체 단위 테스트
2. `scripts/check-layout.ps1`
3. `scripts/validate-skeleton.ps1` — 공식 스켈레톤 **필수 파일 존재**만 검사한다. 환경변수 이름, Compose 제약, `*def-lock` 앵커 내용은 이 스크립트가 검증하지 않는다.
4. 병합된 Compose 설정과 실제 이미지 빌드 — `team1-defender.build.context`가 저장소 `agents/defender`인지 확인한 뒤 이미지를 빌드한다.
5. 공식 스켈레톤 라이브 스모크 — 공격·방어를 동시에 기동하고, 시작 로그가 `policy_source=active`, `bundle_id=defender-2026-08-21-p2r4-satdiag-portal`, `drop_capable_rules=14`, `demotions=[]`인지 확인한다. PACKET→VERDICT·HEARTBEAT·재연결을 확인한다.

## 2. 계약 구분

공식 스켈레톤이 방어 에이전트에 주입하는 변수는 `LLM_BASE_URL`과 `LLM_API_KEY`이다. `AGENT_SOCKET`은 미주입 시 런타임 기본값 `/run/agent.sock`을 쓴다.

| 변수 | 지위 |
|---|---|
| `AGENT_SOCKET` | 공식 계약. 기본값 `/run/agent.sock` |
| `LLM_BASE_URL` · `LLM_API_KEY` | 공식 주입 계약 |
| `LLM_MODEL` | 운영 주입값을 사용하지 않고 내부 기본값 `gpt-5.6-sol` 강제 |
| `PHASE` · `LAYER` · `ROUND` · `TEAM_ID` | 공식 계약 아님. 런타임이 요구하지 않는다 |

Dockerfile: `COPY policy /policy`. 런타임 기본 policy 경로는 패키지 `/app/aegis_defender` 기준 `../../policy` 이므로 컨테이너에서는 `/policy`여야 한다. `/app/policy`에 두면 `policy_source=empty`가 된다.

`USER 65534`. 제16조 방어 락(`cap-drop ALL`·`no-new-privileges`·`mem_reservation 2g`·`cpu_shares 2048`·`pids_limit 512`·`broker1:/run`)은 스켈레톤 `*def-lock`이 적용한다. 우리 override는 `build.context`와 `image`만 바꾼다.

## 3. 절차

`<스켈레톤-루트>`는 팀 내부 채널로 받은 공식 스켈레톤(`deploy/`의 부모) 경로. 저장소에는 이 경로를 기록하지 않는다.

```powershell
$ErrorActionPreference = 'Stop'

# (게이트 1) 방어 단위 테스트
Set-Location agents/defender
python -m unittest discover -s tests -t .
if ($LASTEXITCODE -ne 0) { throw 'defender unit tests failed' }
Set-Location ../..

# (게이트 2) 저장소 레이아웃
pwsh -NoProfile -File scripts/check-layout.ps1
if ($LASTEXITCODE -ne 0) { throw 'check-layout failed' }

# (게이트 3) 스켈레톤 필수 파일 존재
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath "<스켈레톤-루트>"
if ($LASTEXITCODE -ne 0) { throw 'validate-skeleton failed' }

# (게이트 4) 병합 Compose context 검증 + 로컬 이미지 빌드
pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath "<스켈레톤-루트>" -ConfigOnly
if ($LASTEXITCODE -ne 0) { throw 'compose context check failed' }
docker buildx build --platform linux/amd64 --load -t aegis/defender:latest agents/defender
if ($LASTEXITCODE -ne 0) { throw 'docker build failed' }
if ((docker image inspect aegis/defender:latest --format '{{.Os}}/{{.Architecture}}') -ne 'linux/amd64') { throw 'defender image platform mismatch' }

# (게이트 5) 스켈레톤 위 공격·방어 동시 기동
pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath "<스켈레톤-루트>"
if ($LASTEXITCODE -ne 0) { throw 'skeleton live smoke up failed' }
# 운영 페이지 또는 POST /control/start 로 라운드를 연 뒤, 스켈레톤 이미지로 바뀐 공/방을 되돌린다.
pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath "<스켈레톤-루트>" -ReapplyAgents
if ($LASTEXITCODE -ne 0) { throw 'reapply team agent images failed' }
pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath "<스켈레톤-루트>" -LogsDefender
# 시작 로그에서 policy_source=active, bundle_id=defender-2026-08-21-p2r4-satdiag-portal,
# drop_capable_rules=14, demotions=[] 를 확인한다.
# 정리: named volume은 유지한다. down -v 를 쓰지 않는다.
pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath "<스켈레톤-루트>" -Down
if ($LASTEXITCODE -ne 0) { throw 'skeleton down failed' }

# (배포) 팀별 레지스트리 토큰으로 로그인 후 공식 태그·push (제14조)
# 토큰은 운영진이 개별 전달한다. Git·이미지·채팅 로그에 남기지 않는다.
echo "<TEAM-N-TOKEN>" | docker login ligacr.azurecr.io -u team{N}-token --password-stdin
if ($LASTEXITCODE -ne 0) { throw 'docker login failed' }
docker tag aegis/defender:latest ligacr.azurecr.io/team{N}/defender:latest
if ($LASTEXITCODE -ne 0) { throw 'docker tag failed' }
docker push ligacr.azurecr.io/team{N}/defender:latest
if ($LASTEXITCODE -ne 0) { throw 'docker push failed' }
```

`-ConfigOnly`는 `up` 없이 병합 Compose를 읽고 `team1-attacker`와 `team1-defender`의 `build.context`가 각각 저장소 경로인지 검사한다.

## 4. 계약·함정 체크

- **공식 이미지 이름(제14조)**: `ligacr.azurecr.io/team{N}/defender:latest`. 로컬 QA 이름 `aegis/defender:latest`를 그대로 올리지 않는다.
- **로그인(제14조)**: `docker login ligacr.azurecr.io -u team{N}-token`.
- **실행 사용자**: 이미지 `USER 65534`. compose `user:`를 덮어쓰지 않는다.
- **소켓**: volume `broker1:/run`, 기본 `AGENT_SOCKET=/run/agent.sock`.
- **정책 경로**: 이미지 안 `/policy/active.json`. `/app/policy`가 아니다.
- **비밀·주소·경로 미포함(제7·16조)**: 키·토큰·개인 절대경로를 이미지·저장소에 남기지 않는다.
- **Compose 경로**: 상대경로는 첫 번째 `-f` 파일 기준이다. `AEGIS_DEFENDER_CONTEXT`를 사용한다.
- **시작 로그**: `policy_source=active`, `bundle_id=defender-2026-08-21-p2r4-satdiag-portal`, `drop_capable_rules=14`, `demotions=[]`가 정상이다. HTTP 정밀 규칙 9개에 SatDiag(`9000`) Tail/Export 2개와 P2-R3 GraphQL(`8082`) `missionAudit` 차단 1개를 더한 12개가 ACTIVE이고, 나머지 휴리스틱은 SHADOW다. 플래그 유출이 연결되지 않은 `systemConfig` 조회는 이 ACTIVE 규칙에 포함하지 않는다.
- **운영 페이지 시작 재생성**: backend `POST /control/start`는 combatant를 스켈레톤 이미지로 force-recreate한다. 로컬 스모크에서 라운드를 연 뒤에는 `-ReapplyAgents`로 team1-attacker·team1-defender를 팀 이미지로 되돌리고, 실행 중 이미지가 override 값인지 확인한다. 이 단계 없이 로그를 보면 스켈레톤 레퍼런스 에이전트를 검증하게 된다. 본선은 Registry `latest`를 쓰므로 이 절차가 필요 없다.

## 5. 설계상 의도된 범위

- 원격 LLM 호출은 패킷별 동기 verdict 경로에 넣지 않는다.
- policy를 못 읽어도 HEARTBEAT와 ACCEPT 경로는 유지한다. 다만 배포 이미지는 active bundle을 로드해야 한다.

## 6. 남은 팀 작업(참고)

팀 번호와 Registry 토큰이 없으면 로컬 빌드와 스켈레톤 스모크까지만 수행하고 push는 보류한다.
