# 외부 스켈레톤 연동

공식 스켈레톤은 이 저장소에 포함하지 않습니다.

## 현재 가능한 검사

```powershell
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath <스켈레톤-루트>
```

검사 대상은 Compose 파일, 공식 에이전트 가이드, Team 1 Dockerfile, Broker 바이너리입니다.

스켈레톤 루트 바로 아래에 이 저장소를 배치한 경우에는 다음 명령을 사용할 수 있습니다.

```powershell
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath ..
```

다른 배치에서는 `..`를 사용하지 말고 각 팀원의 실제 스켈레톤 루트를 인자로 전달합니다. 저장소 파일에는 팀원 개인의 절대경로를 기록하지 않습니다.

## 이미지 제출 계약

다음 항목은 `FINALS-RULES` 및 당일 운영 안내에서 확인한 운영 규칙입니다.

- 공격 이미지: `ligacr.azurecr.io/team{N}/attacker:latest`
- 방어 이미지: `ligacr.azurecr.io/team{N}/defender:latest`
- 운영진은 라운드 시작 5분 전에 `latest`를 pull하며 pull timeout은 20분입니다.

## 스켈레톤 확인 대기 제약

다음 제한은 `OFFICIAL-SKELETON`과 `deploy/docs/agent-guide.md`를 실제로 검증한 뒤에만 Docker 구현 계약으로 확정합니다. 현재는 확정된 본선 규칙으로 취급하지 않습니다.

- 공통: `no-new-privileges`, memory reservation `2g`, CPU shares `2048`, PID limit `512`
- 방어: Linux capability 전체 제거(`cap-drop ALL`)

비밀값, 환경별 주소, Broker socket 경로도 이미지에 넣지 않습니다. 실제 주입 방식과 mount 요구사항은 공식 스켈레톤과 공식 에이전트 가이드를 검증해 확정합니다.

## 로컬 QA와 본선 배포

로컬 QA에서는 공식 파일을 복사하거나 수정하지 않고 Compose override로 Team 1의 빌드 컨텍스트만 이 저장소의 에이전트로 바꿉니다. 환경변수와 socket 구성은 스켈레톤이 주입한 값을 보존합니다.

본선 배포에서는 로컬 build override에 의존하지 않습니다. 운영진이 Registry의 `latest` 이미지를 pull하여 실행합니다. Dockerfile, `compose.agents.yml`, `run-with-skeleton.ps1`을 추가하기 전에는 위의 스켈레톤 확인 대기 제약을 검증해야 합니다. Docker 변경에는 해당 에이전트 소유자와 팀장 검토가 필요합니다.
