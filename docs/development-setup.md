# 개발 환경 시작 방법

## 다음 Codex 세션에서 열 폴더

다음부터는 아래 폴더 자체를 작업 공간으로 엽니다.

```text
C:\Users\mamekuma\Downloads\DAH2026_스켈레톤코드\Aegis.D4H-DAH2026
```

상위 `DAH2026_스켈레톤코드` 폴더를 열 필요는 없습니다. Codex 또는 편집기에서 `Aegis.D4H-DAH2026`를 직접 선택합니다.

Visual Studio Code를 사용하는 경우 PowerShell에서 다음과 같이 엽니다.

```powershell
cd C:\Users\mamekuma\Downloads\DAH2026_스켈레톤코드\Aegis.D4H-DAH2026
code .
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
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath ..
```

현재 배치에서는 저장소의 부모가 공식 스켈레톤 루트이므로 `..`를 사용할 수 있습니다. 저장소를 다른 위치로 옮기면 실제 스켈레톤 경로를 명시합니다.

## 비밀값

`.env.example`을 참고해 개인용 `.env`를 만들 수 있지만 `.env`는 Git에 커밋하지 않습니다. `LLM_API_KEY`, `SUBMIT_TOKEN`, Registry 자격증명을 문서나 로그에 남기지 않습니다.
