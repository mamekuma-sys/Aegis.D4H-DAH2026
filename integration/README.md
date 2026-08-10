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

- 공격 이미지: `ligacr.azurecr.io/team{N}/attacker:latest`
- 방어 이미지: `ligacr.azurecr.io/team{N}/defender:latest`
- 운영진은 라운드 시작 5분 전에 `latest`를 pull하며 pull timeout은 20분입니다.
- 컨테이너는 라운드마다 새로 생성되고 종료 후 삭제됩니다. 이미지 시작 시간도 라운드 시간에 포함되므로 시작 경로를 짧게 유지합니다.

## 실행 제한

- 공통: `no-new-privileges`, memory reservation `2g`, CPU shares `2048`, PID limit `512`
- 방어: Linux capability 전체 제거(`cap-drop ALL`)와 Broker socket mount
- 비밀값과 환경별 주소는 이미지에 넣지 않고 운영진이 주입하는 환경변수와 socket만 사용합니다.

## 후속 단계

공격·방어 Dockerfile이 각각 구현되면 `compose.agents.yml`과 `run-with-skeleton.ps1`을 추가합니다. `compose.agents.yml`은 공식 파일을 복사하지 않고 팀 이미지, 운영진이 주입하는 환경변수, 방어 Broker socket mount만 override해야 합니다. Docker 변경에는 해당 에이전트 소유자와 팀장 검토가 필요합니다. 이 파일들은 Team 1의 빌드 컨텍스트만 팀 저장소의 에이전트로 교체해야 하며, 공식 스켈레톤 파일을 수정하거나 복사하지 않습니다.
