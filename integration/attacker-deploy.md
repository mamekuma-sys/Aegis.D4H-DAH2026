# 공격 에이전트 배포 런북 (handoff)

배포 담당자를 위한 운영 문서. 코드/설계 근거는 `docs/superpowers/specs/2026-08-11-attacker-runtime-design.md`,
계약은 `docs/references/rules-checklist.md`·`integration/README.md`를 참조한다.

## 1. 현재 검증 상태 (기준일 2026-08-13)

이미 통과한 항목(재확인 불필요):

- 어태커 런타임 `main` 병합 완료. 단위 테스트 159개 통과(`python -m unittest`).
- 공식 스켈레톤 통합 정적 검증 통과: `validate-skeleton.ps1` OK.
- 환경변수 계약이 스켈레톤과 **정확히 일치**: `TARGETS`·`PORTS`·`SUBMIT_URL`·`SUBMIT_TOKEN`·`LLM_BASE_URL`·`LLM_API_KEY`·`LLM_MODEL(gpt-4o-mini)`.
- Dockerfile 런타임 경로(`COPY`/`WORKDIR`/`CMD`) 검증: `PYTHONPATH` 없이 `python -m aegis_attacker`가 기동하고, 설정 없으면 `inert` 로그 후 종료(fail-open).
- 제16조 런타임 제약(`no-new-privileges`·`mem_reservation 2g`·`cpu_shares 2048`·`pids_limit 512`)은 스켈레톤 compose의 `*att-lock` 앵커가 적용한다. 우리 override(`compose.agents.yml`)는 `build.context`와 `image`만 바꾸므로 이 값들을 보존한다.

## 2. 배포 전 통과해야 할 게이트 (아직 안 돌림 — Docker 필요)

개발 셸에 Docker가 없어 아래 둘은 미실행 상태다. Registry push 전에 **반드시** 한 번 통과시킨다.

1. 실제 이미지 빌드가 성공하는가.
2. 스켈레톤 위 라이브 스모크에서 어태커가 표적을 관측·시도하고, flag를 잡으면 제출 API로 보내는가.

## 3. 절차

`<스켈레톤-루트>`는 팀 내부 채널로 받은 공식 스켈레톤(`deploy/`의 부모) 경로. 저장소에는 이 경로를 기록하지 않는다.

```powershell
# (게이트 1) 로컬 빌드
docker build -t aegis/attacker:latest agents/attacker

# (게이트 2) 스켈레톤 위 라이브 스모크 — 공/방 기동 후 공격 로그 확인
pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath "<스켈레톤-루트>"
docker compose -f "<스켈레톤-루트>/deploy/docker-compose.yml" -f integration/compose.agents.yml logs -f team1-attacker
# 정리: pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath "<스켈레톤-루트>" -Down

# (배포) 공식 태그로 재태그 — team 번호 확인 (제14조)
docker tag aegis/attacker:latest ligacr.azurecr.io/team{N}/attacker:latest

# (배포) ACR 로그인 후 push
az acr login --name ligacr
docker push ligacr.azurecr.io/team{N}/attacker:latest
```

## 4. 계약·함정 체크

- **공식 이미지 이름(제14조)**: `ligacr.azurecr.io/team{N}/attacker:latest`. 로컬 QA 이름 `aegis/attacker:latest`를 그대로 올리지 않는다. `team{N}`의 N을 우리 팀 번호로 확인.
- **pull 타이밍(제15조)**: 운영진이 라운드 시작 5분 전 `latest`를 pull(타임아웃 20분), 컨테이너는 라운드마다 새로 생성·삭제된다. 이미지 시작 시간도 라운드 시간에 포함되므로 시작 경로를 늘리지 않는다.
- **비밀·주소·경로 미포함(제7·16조)**: `TARGETS`/토큰/키는 이미지에 굽지 않고 운영진 주입 환경변수로만 참조한다. 이미지·저장소에 개인 절대경로를 남기지 않는다.
- **LLM 변수 이름**: 어태커는 `LLM_BASE_URL`·`LLM_API_KEY`를 읽는다(스켈레톤 compose `*llm` 앵커가 주입). `LLM_UPSTREAM_*`는 `litellm-gw` 프록시의 상류 설정이므로 혼동 금지. 라이브 스모크에서 LLM 경로까지 태우려면 스켈레톤 `.env`의 `LLM_UPSTREAM_KEY`가 있어야 하며, 없으면 LLM 조언 경로만 fail-open되고 결정론 경로는 정상 동작한다.
- **서비스명/프로필**: override는 스켈레톤 서비스 `team1-attacker`(`profiles: ["combat"]`)에만 병합된다. 스켈레톤 서비스명이 바뀌면 override도 갱신해야 한다.

## 5. 설계상 의도된 범위 (배포에 문제 없음)

- 어태커는 **읽기 전용 기본**이다. 상태 변경(mutating) 공격은 deny-by-default이며, 본선 인터페이스를 관측·검토하기 전까지 action 레지스트리를 비워 둔다(설계 §9.10, 계획 Task 4). 이 상태로 배포해도 규칙 위반이 아니다.
- 본선 인터페이스가 확정되면 재검토할 항목: LLM 조언이 낼 수 있는 `POST`의 부작용 재분류, mutating action 레지스트리 채우기.

## 6. 남은 팀 작업(참고)

Registry 접근·태그 규칙·push 권한은 팀장/운영 담당이 확정한다. 이 저장소에는 아직 공식 Registry 배포 절차 문서가 없으므로, 확정 시 이 런북에 반영한다.
