# 개발 환경 시작 방법

## 최초 내려받기

각 팀원은 원하는 작업 디렉터리에서 저장소를 clone합니다.

```powershell
git clone https://github.com/mamekuma-sys/Aegis.D4H-DAH2026.git
Set-Location Aegis.D4H-DAH2026
code .
```

Codex 또는 다른 편집기에서는 clone된 `Aegis.D4H-DAH2026` 폴더 자체를 작업 공간으로 선택합니다. 특정 드라이브, 사용자 홈 또는 상위 폴더 이름을 저장소 설정에 기록하지 않습니다.

이미 clone한 저장소를 다시 열 때는 `.git`, `AGENTS.md`, `README.md`가 있는 저장소 루트를 선택합니다. 터미널에서는 현재 저장소 루트를 다음 명령으로 확인할 수 있습니다.

```powershell
git rev-parse --show-toplevel
```

## 작업 시작 점검

```powershell
git switch main
git pull --ff-only
git status --short --branch
pwsh -NoProfile -File scripts/check-layout.ps1
```

기능 개발은 `main`에 바로 작성하지 않고 담당별 브랜치를 만듭니다.

```powershell
git switch -c feat/attacker-<topic>
git switch -c feat/defender-<topic>
```

한 번에 하나의 예시만 실행하며 `<topic>`은 `scenario-planner`, `broker-protocol`처럼 실제 작업 이름으로 바꿉니다.

## 공식 스켈레톤 사용

공식 스켈레톤은 이 저장소 바깥에 유지합니다. 경로를 코드나 Git 설정에 하드코딩하지 않고 검증 스크립트에 인자로 전달합니다.

```powershell
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath <본인-스켈레톤-루트>
```

예를 들어 저장소와 스켈레톤을 같은 작업 디렉터리 아래의 형제 폴더로 배치했다면 상대경로를 사용할 수 있습니다.

```text
workspace/
├─ Aegis.D4H-DAH2026/
└─ DAH2026_스켈레톤코드/
```

```powershell
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath ..\DAH2026_스켈레톤코드
```

스켈레톤 루트 바로 아래에 이 저장소를 배치한 경우에만 `-SkeletonPath ..`가 유효합니다. 팀원별 배치가 다를 수 있으므로 공통 문서나 스크립트에 해당 상대경로를 기본값으로 고정하지 않습니다.

## 비밀값

`.env.example`을 참고해 개인용 `.env`를 만들 수 있지만 `.env`는 Git에 커밋하지 않습니다. `LLM_API_KEY`, `SUBMIT_TOKEN`, Registry 자격증명을 문서나 로그에 남기지 않습니다.
