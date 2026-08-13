# 공격 에이전트 배포 런북 (handoff)

배포 담당자를 위한 운영 문서. 코드/설계 근거는 `docs/superpowers/specs/2026-08-11-attacker-runtime-design.md`,
계약은 `docs/references/rules-checklist.md`·`integration/README.md`를 참조한다.

## 1. 배포마다 다시 통과할 게이트

이전 날짜의 통과 기록을 재사용하지 않는다. Registry push 전에 현재 커밋에서 아래를 **다시** 실행한다.

1. 공격 에이전트 전체 단위 테스트
2. `scripts/check-layout.ps1`
3. `scripts/validate-skeleton.ps1` — 공식 스켈레톤 **필수 파일 존재**만 검사한다. 환경변수 이름, Compose 제약, `*att-lock` 앵커 내용은 이 스크립트가 검증하지 않는다.
4. 병합된 Compose 설정과 실제 이미지 빌드 — `team1-attacker.build.context`가 저장소 `agents/attacker`인지 확인한 뒤 이미지를 빌드한다.
5. 공식 스켈레톤 라이브 스모크 — 어태커가 표적을 관측·시도하고, flag를 잡으면 제출 API로 보낸다.

## 2. 계약 구분

공식 스켈레톤이 공격 에이전트에 주입하는 LLM 변수는 `LLM_BASE_URL`과 `LLM_API_KEY`뿐이다.

| 변수 | 지위 |
|---|---|
| `TARGETS` · `PORTS` · `SUBMIT_URL` · `SUBMIT_TOKEN` | 공식 주입 계약 |
| `LLM_BASE_URL` · `LLM_API_KEY` | 공식 주입 계약 |
| `LLM_MODEL` | 팀 코드의 선택 옵션. 미주입 시 내부 기본값 `gpt-4o-mini` |

`LLM_UPSTREAM_*`는 `litellm-gw` 프록시의 상류 설정이며 에이전트 계약이 아니다.

Dockerfile 런타임 경로(`COPY`/`WORKDIR`/`CMD`): `PYTHONPATH` 없이 `python -m aegis_attacker`가 기동하고, 설정이 없으면 `inert` 로그 후 종료(fail-open)해야 한다.

제16조 런타임 제약(`no-new-privileges`·`mem_reservation 2g`·`cpu_shares 2048`·`pids_limit 512`)은 스켈레톤 compose의 `*att-lock` 앵커가 적용한다. 우리 override는 `build.context`와 `image`만 바꾸므로 이 값들을 보존해야 한다. 보존 여부는 라이브 스모크 전에 `docker compose ... config`로 확인한다.

## 3. 절차

`<스켈레톤-루트>`는 팀 내부 채널로 받은 공식 스켈레톤(`deploy/`의 부모) 경로. 저장소에는 이 경로를 기록하지 않는다.

```powershell
# (게이트 1) 공격 단위 테스트
Set-Location agents/attacker
python -m unittest discover -s tests -t .
Set-Location ../..

# (게이트 2) 저장소 레이아웃
pwsh -NoProfile -File scripts/check-layout.ps1

# (게이트 3) 스켈레톤 필수 파일 존재
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath "<스켈레톤-루트>"

# (게이트 4) 병합 Compose context 검증 + 로컬 이미지 빌드
pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath "<스켈레톤-루트>" -ConfigOnly
docker build -t aegis/attacker:latest agents/attacker

# (게이트 5) 스켈레톤 위 라이브 스모크 — 공/방 기동 후 공격 로그 확인
pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath "<스켈레톤-루트>"
pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath "<스켈레톤-루트>" -Logs
# 정리:
pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath "<스켈레톤-루트>" -Down

# (배포) 공식 태그로 재태그 — team 번호 확인 (제14조)
docker tag aegis/attacker:latest ligacr.azurecr.io/team{N}/attacker:latest

# (배포) 팀별 레지스트리 토큰으로 로그인 후 push (제14조)
# 토큰은 운영진이 개별 전달한다. Git·이미지·채팅 로그에 남기지 않는다.
echo "<TEAM-N-TOKEN>" | docker login ligacr.azurecr.io -u team{N}-token --password-stdin
docker push ligacr.azurecr.io/team{N}/attacker:latest
```

`-ConfigOnly`는 `up` 없이 병합 Compose를 읽고 `team1-attacker.build.context`가 저장소 `agents/attacker`인지 검사한다. 상대경로 `../agents/attacker` 또는 `<스켈레톤-루트>/agents/attacker`이면 실패한다.

## 4. 계약·함정 체크

- **공식 이미지 이름(제14조)**: `ligacr.azurecr.io/team{N}/attacker:latest`. 로컬 QA 이름 `aegis/attacker:latest`를 그대로 올리지 않는다. `team{N}`의 N을 우리 팀 번호로 확인.
- **로그인(제14조)**: `docker login ligacr.azurecr.io -u team{N}-token`. Azure CLI(`az acr login`)가 공식 제출 경로가 아니다.
- **pull 타이밍(제15조)**: 운영진이 라운드 시작 5분 전 `latest`를 pull(타임아웃 20분), 컨테이너는 라운드마다 새로 생성·삭제된다. 이미지 시작 시간도 라운드 시간에 포함되므로 시작 경로를 늘리지 않는다.
- **비밀·주소·경로 미포함(제7·16조)**: `TARGETS`/토큰/키는 이미지에 굽지 않고 운영진 주입 환경변수로만 참조한다. 이미지·저장소에 개인 절대경로를 남기지 않는다.
- **LLM 변수 이름**: 공식 주입은 `LLM_BASE_URL`·`LLM_API_KEY`. 라이브 스모크에서 LLM 경로까지 태우려면 스켈레톤 `.env`의 `LLM_UPSTREAM_KEY`가 있어야 하며, 없으면 LLM 조언 경로만 fail-open되고 결정론 경로는 정상 동작한다.
- **서비스명/프로필**: override는 스켈레톤 서비스 `team1-attacker`(`profiles: ["combat"]`)에만 병합된다. 스켈레톤 서비스명이 바뀌면 override도 갱신해야 한다.
- **Compose 경로**: 여러 `-f` 병합 시 상대경로는 첫 번째 Compose 파일 기준이다. override에 저장소 상대경로를 두지 말고 `run-with-skeleton.ps1`이 주입하는 `AEGIS_ATTACKER_CONTEXT`를 사용한다.

## 5. 설계상 의도된 범위 (배포에 문제 없음)

- 어태커는 **읽기 전용 기본**이다. 상태 변경(mutating) 공격은 deny-by-default이며, 본선 인터페이스를 관측·검토하기 전까지 action 레지스트리를 비워 둔다(설계 §9.10, 계획 Task 4). 이 상태로 배포해도 규칙 위반이 아니다.
- 본선 인터페이스가 확정되면 재검토할 항목: LLM 조언이 낼 수 있는 `POST`의 부작용 재분류, mutating action 레지스트리 채우기.

## 6. 남은 팀 작업(참고)

팀 번호와 Registry 토큰 전달 시점은 팀장/운영진이 확정한다. 토큰을 받기 전에는 로컬 빌드와 스켈레톤 스모크까지만 수행한다.
