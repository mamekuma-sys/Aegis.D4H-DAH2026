# 외부 스켈레톤 연동

공식 스켈레톤은 이 저장소에 포함하지 않습니다.

> 공격 이미지 빌드·라이브 스모크·Registry 배포 절차는 `integration/attacker-deploy.md`를 참조합니다.
> 방어 이미지 절차는 `integration/defender-deploy.md`를 참조합니다.
>
> 여러 Compose 파일을 `-f`로 병합하면 상대경로는 override 파일이 아니라 첫 번째 Compose 파일 기준으로 해석됩니다. `compose.agents.yml`은 저장소 상대경로를 쓰지 않고, `run-with-skeleton.sh` 또는 `.ps1`이 `AEGIS_ATTACKER_CONTEXT`와 `AEGIS_DEFENDER_CONTEXT`에 저장소 절대경로를 넣어 주입합니다. 개인 절대경로는 Git에 기록하지 않습니다.
>
> 로컬 스모크에서 운영 페이지 또는 `POST /control/start`로 라운드를 열면 Team 1 컨테이너가 스켈레톤 이미지로 다시 만들어집니다. 그 뒤에는 macOS/Linux의 `--reapply-agents` 또는 PowerShell의 `-ReapplyAgents`로 팀 이미지를 되돌리고 실행 중 이미지를 검사합니다.

## 현재 가능한 검사

```bash
bash scripts/validate-skeleton.sh <스켈레톤-루트>
```

검사 대상은 Compose 파일, 공식 에이전트 가이드, Team 1 Dockerfile, Broker 바이너리입니다.

스켈레톤 루트 바로 아래에 이 저장소를 배치한 경우에는 다음 명령을 사용할 수 있습니다.

```bash
bash scripts/validate-skeleton.sh ..
```

다른 배치에서는 `..`를 사용하지 말고 각 팀원의 실제 스켈레톤 루트를 인자로 전달합니다. 저장소 파일에는 팀원 개인의 절대경로를 기록하지 않습니다.

## macOS/Linux 로컬 스모크

```bash
bash integration/run-with-skeleton.sh <스켈레톤-루트> --config-only
bash integration/run-with-skeleton.sh <스켈레톤-루트>
bash integration/run-with-skeleton.sh <스켈레톤-루트> --reapply-agents
bash integration/run-with-skeleton.sh <스켈레톤-루트> --logs-defender
bash integration/run-with-skeleton.sh <스켈레톤-루트> --down
```

Compose override가 공격·방어 이미지 모두 `linux/amd64`로 빌드·실행하도록 강제합니다.
실행 스크립트는 Docker Compose plugin(`docker compose`)을 우선 사용하고, 없으면
Homebrew 등으로 설치한 standalone `docker-compose`를 자동으로 사용합니다.
Apple Silicon에서 공식 x86-64 Broker의 NFQUEUE까지 실기 검증할 때는 단순 컨테이너
에뮬레이션이 아니라 x86_64 Linux VM을 사용해야 합니다.

## 이미지 제출 계약

다음 항목은 `FINALS-RULES` 제14조와 제15조에서 확인한 운영 규칙입니다. `FINALS-DAY-NOTE`는 파생 팀 메모이므로 이 계약의 공식 원본으로 인용하지 않습니다.

- `FINALS-RULES` 제14조: 공격 이미지 `ligacr.azurecr.io/team{N}/attacker:latest`
- `FINALS-RULES` 제14조: 방어 이미지 `ligacr.azurecr.io/team{N}/defender:latest`
- `FINALS-RULES` 제15조: 운영진은 라운드 시작 5분 전에 `latest`를 pull하며 pull timeout은 20분입니다.
- `FINALS-RULES` 제15조: 컨테이너는 라운드마다 새로 생성되고 종료 후 삭제됩니다.

## 공식 실행 제약과 스켈레톤 구현 확인

`FINALS-RULES` 제16조는 다음 실행 값을 공식 규칙으로 고정합니다.

- 공통: `no-new-privileges`, memory reservation `2g`, CPU shares `2048`, PID limit `512`
- 방어: Linux capability 전체 제거(`cap-drop ALL`)와 Broker socket mount
- 운영 환경변수는 실행 시 주입하며 이미지에 고정하지 않음

`OFFICIAL-SKELETON`과 `deploy/docs/agent-guide.md` 검증은 위 값의 공식 여부를 다시 결정하는 단계가 아닙니다. 실제 Compose 옵션, socket mount, 환경변수 주입 구현이 `FINALS-RULES` 제16조와 최신 운영진 직접 안내에 맞는지 확인하는 단계입니다. 비밀값, 환경별 주소, Broker socket 경로는 이미지에 넣지 않습니다.

## 로컬 QA와 본선 배포

로컬 QA에서는 공식 파일을 복사하거나 수정하지 않고 Compose override로 Team 1의 빌드 컨텍스트만 이 저장소의 에이전트로 바꿉니다. 환경변수와 socket 구성은 스켈레톤이 주입한 값을 보존합니다.

본선 배포에서는 로컬 build override에 의존하지 않습니다. 운영진이 Registry의 `latest` 이미지를 pull하여 실행합니다. Dockerfile, `compose.agents.yml`, 두 플랫폼의 `run-with-skeleton` 스크립트를 추가하기 전에는 공식 스켈레톤의 실제 구현이 위 공식 실행 제약과 일치하는지 검증해야 합니다. Docker 변경에는 해당 에이전트 소유자와 팀장 검토가 필요합니다.
