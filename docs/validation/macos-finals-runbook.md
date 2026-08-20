# macOS 본선 Break 운영 런북

## 목표

같은 Python Break Copilot을 macOS의 zsh와 PowerShell Core에서 모두 실행한다. 원본 PCAP·로그와
스켈레톤은 저장소 밖에 두고, LLM 분석 결과와 패치는 격리된 candidate worktree에서만 검증한다.
두 셸은 같은 Git 저장소와 환경변수를 사용하지만 서로 다른 터미널 프로세스이므로 환경변수는 각
터미널에 별도로 설정한다.

## 전날 준비

필수 도구는 zsh, PowerShell Core(`pwsh`), Python 3.12 이상, Git, Docker Desktop의 Linux
container daemon, Docker Compose v2, Docker Buildx다. `tshark`는 필수는 아니지만 없으면 PCAP
분석이 metadata-only로 제한된다. Apple Silicon에서도 제출 이미지는 항상 `linux/amd64`로 빌드한다.
공식 x86-64 Broker의 NFQUEUE 실기는 단순 Docker 에뮬레이션이 아니라 x86_64 Linux VM이 필요하다.

Docker Desktop을 먼저 실행하고 검증용 이미지를 한 번만 준비한다.

```zsh
docker pull python:3.12-slim
zsh scripts/macos-preflight.zsh --skeleton <스켈레톤-루트>
```

PowerShell 진입점도 같은 Python을 찾는지 확인한다.

```powershell
pwsh -NoProfile -File scripts/break-copilot.ps1 preflight --require-docker
```

## LLM 환경변수

키 값을 명령 이력이나 파일에 직접 쓰지 않는다. zsh에서는 숨김 입력으로 현재 터미널에만 넣는다.

```zsh
export LLM_BASE_URL='<운영진-제공-URL>'
read -rs 'LLM_API_KEY?LLM API key: '
export LLM_API_KEY
print
zsh scripts/macos-preflight.zsh --require-llm --skeleton <스켈레톤-루트>
```

PowerShell 터미널에서는 별도로 설정한다.

```powershell
$env:LLM_BASE_URL = '<운영진-제공-URL>'
$env:LLM_API_KEY = Read-Host -MaskInput 'LLM API key'
pwsh -NoProfile -File scripts/break-copilot.ps1 preflight --require-llm --require-docker
```

터미널을 닫으면 다시 주입한다. `.env`, 셸 profile, Git 파일에는 저장하지 않는다.

## Break 실행

다운로드한 공식 아카이브와 압축 해제 폴더는 저장소 밖 `<break-inbox>`에 둔다. 현재 공식
`teamN-round.tar.gz` 직접 해제 지원과 Linux SLL/SLL2 replay는 별도 호환 게이트이므로, 해결 전에는
아카이브를 사람이 안전하게 별도 폴더에 풀고 replay 결과를 READY 근거로 승격하지 않는다.

zsh:

```zsh
zsh scripts/break-copilot.zsh ingest \
  --input <break-inbox/round-N> --side defender

zsh scripts/break-copilot.zsh run \
  --input <break-inbox/round-N> \
  --side defender \
  --candidate <candidate-worktree> \
  --base-ref HEAD \
  --skeleton-path <스켈레톤-루트>
```

PowerShell:

```powershell
pwsh -NoProfile -File scripts/break-copilot.ps1 run `
  --input <break-inbox/round-N> `
  --side defender `
  --candidate <candidate-worktree> `
  --base-ref HEAD `
  --skeleton-path <스켈레톤-루트>
```

LLM 호출이 불가능하면 `ingest`까지만 실행하고 코드 상태를 바꾸지 않는다. LLM 제안은 기존 승인
절차를 대체하지 않는다.

## 스크리미지와 제출

zsh에서 image-only 스크리미지 구성을 검사한다.

```zsh
zsh integration/scrimmage/run-scrimmage.zsh \
  --skeleton <스켈레톤-루트> \
  --attacker-image <attacker-image> \
  --defender-image <defender-image> \
  --config-only
```

PowerShell에서는 기존 `integration/scrimmage/run-scrimmage.ps1`을 사용한다. 현재 스크리미지는
Team 1의 두 이미지만 교체하므로 직접적인 공격자 대 방어자 2-leg 검증으로 간주하지 않는다.

승인된 clean candidate를 zsh에서 빌드만 하는 명령은 다음과 같다.

```zsh
zsh integration/promote-candidate.zsh \
  --candidate <candidate-worktree> \
  --evaluation <evaluation.json> \
  --rubric <combined-rubric.json> \
  --approval <approval.json> \
  --agent defender \
  --team-number <팀번호>
```

Registry를 변경하려면 같은 명령에 `--push`를 명시한다. PowerShell에서는 `-Push`를 사용한다.
팀이 `latest`를 **push**하고 운영진이 공지된 시점에 **pull**한다. 마감 직전에는 push 결과 digest와
Registry 로그인 상태를 사람이 다시 확인한다.

## 종료 전 확인

- 원본 PCAP·로그·아카이브가 Git 상태에 나타나지 않는다.
- candidate가 clean commit이고 evaluation·rubric·approval digest가 일치한다.
- 이미지가 `linux/amd64`이며 `LLM_API_KEY`, `SUBMIT_TOKEN` 값을 포함하지 않는다.
- Defender 변경은 실제 Broker 300ms·heartbeat·reconnect 증거 없이는 READY가 아니다.
- 자동 push를 사용하지 않았고, 마지막 Registry 변경은 사람이 명시적으로 승인했다.
