# 외부 스켈레톤 연동

공식 스켈레톤은 이 저장소에 포함하지 않습니다.

## 현재 가능한 검사

```powershell
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath <스켈레톤-루트>
```

검사 대상은 Compose 파일, 공식 에이전트 가이드, Team 1 Dockerfile, Broker 바이너리입니다.

현재 로컬 배치에서는 저장소의 부모 폴더가 스켈레톤 루트이므로 다음 명령을 사용할 수 있습니다.

```powershell
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath ..
```

## 후속 단계

공격·방어 Dockerfile이 각각 구현되면 `compose.agents.yml`과 `run-with-skeleton.ps1`을 추가합니다. 이 파일들은 Team 1의 빌드 컨텍스트만 팀 저장소의 에이전트로 교체해야 하며, 공식 스켈레톤 파일을 수정하거나 복사하지 않습니다.
