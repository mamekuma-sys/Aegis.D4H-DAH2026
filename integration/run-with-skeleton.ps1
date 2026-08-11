<#
.SYNOPSIS
  스켈레톤 데모 위에서 팀 공격 이미지(team1-attacker)를 교체 실행한다.

.DESCRIPTION
  공식 스켈레톤 docker-compose.yml 과 integration/compose.agents.yml override를 함께 적용해,
  team1-attacker 만 팀 저장소의 aegis_attacker 패키지로 빌드·기동한다. 공식 파일은 수정하지 않는다.
  개인 절대경로는 저장소에 기록하지 않으므로 스켈레톤 루트를 인자로 전달한다.

.PARAMETER SkeletonPath
  공식 스켈레톤 루트(=deploy/ 의 부모). 예: C:\path\to\DAH2026_스켈레톤코드

.EXAMPLE
  pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath C:\Users\me\Downloads\DAH2026_스켈레톤코드
#>
param(
    [Parameter(Mandatory = $true)][string]$SkeletonPath,
    [switch]$Down
)

$ErrorActionPreference = "Stop"
$compose = Join-Path $SkeletonPath "deploy/docker-compose.yml"
$override = Join-Path $PSScriptRoot "compose.agents.yml"

if (-not (Test-Path $compose)) { throw "스켈레톤 compose 없음: $compose" }
if (-not (Test-Path $override)) { throw "override 없음: $override" }

if ($Down) {
    docker compose -f $compose -f $override --profile combat down -v
    return
}

# 공/방 이미지 빌드 + 인프라 기동. LLM 키는 스켈레톤 .env(LLM_UPSTREAM_*)로 주입한다.
docker compose -f $compose -f $override --profile combat up -d --build
Write-Host "→ 운영 페이지: http://localhost:4100 (게임 길이 설정 후 시작)"
Write-Host "→ 공격 로그:  docker compose -f `"$compose`" -f `"$override`" logs -f team1-attacker"
