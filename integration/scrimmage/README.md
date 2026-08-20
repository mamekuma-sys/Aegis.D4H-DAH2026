# SCRIMMAGE_PROXY 실행

공식 스켈레톤 파일을 수정·복사하지 않고 동결된 A0/A1/D0/D1 이미지를 2×2로 검증한다.
결과에는 집계 수치와 SHA-256만 저장하며 raw PCAP·로그·flag·token은 저장하지 않는다.

```powershell
pwsh -NoProfile -File integration/scrimmage/build-proxy-layers.ps1
pwsh -NoProfile -File integration/scrimmage/run-matrix.ps1 `
  -SkeletonPath C:\path\to\official-skeleton -Seeds 1,2,3
pwsh -NoProfile -File integration/scrimmage/judge-results.ps1 `
  -ResultRoot <temporary-result-root> -ExpectedSeeds 1,2,3 -HumanScoreFile PENDING
```

runner는 기존 `lig-demo` 컨테이너가 있으면 중단하고 사용자 상태를 보존한다. 결과 기본 위치는
OS 임시 폴더의 `Aegis.D4H-scrimmage`이며 Git 작업트리 밖이다. 각 경기 후 컨테이너는 제거하지만
공식 스켈레톤의 named volume과 raw archive는 삭제하지 않는다.

경기 시작은 공식 backend의 control API에 맡긴다. runner는 임시 combatant-only Compose
controller를 backend에 읽기 전용으로 연결하여 고정 이미지가 정확히 한 번 생성되게 한다. 이 임시
controller는 공식 스켈레톤을 수정하지 않으며, 정상 종료 시 OS 임시 폴더에서 삭제된다.

Judge는 사람 점수가 `PENDING`이면 필수 게이트가 모두 통과해도 `NOT_READY`를 반환한다. 개발은
seed 3개, 최종 후보는 Arena/Judge만 접근하는 blind seed 5개 이상으로 다시 실행해야 한다.

이 디렉터리는 Docker/Compose 통합 영역이다. 변경 승격에는 Docker owner, 영향받는 agent owner,
팀장 이경준 검토가 필요하고 `contracts/scrimmage/**` 변경은 팀장 승인이 필요하다.
