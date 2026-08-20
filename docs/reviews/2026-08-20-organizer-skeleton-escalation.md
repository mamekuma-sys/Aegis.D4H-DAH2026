# DAH 2026 공식 스켈레톤 결함 및 Round mapping 확인 요청

## 전달 상태

- 수신처가 저장소에 구성돼 있지 않아 이 문서는 운영진 전달용 최종 초안이다.
- raw PCAP/log, flag, token, cookie, credential, 개인 절대경로는 포함하지 않는다.
- 팀은 공식 외부 스켈레톤을 수정하지 않았다.

## 운영진 전달문

안녕하세요. DAH 2026 공식 스켈레톤의 Linux/amd64 로컬 검증 중 challenge 서비스 기동 결함과
Round 식별 충돌을 확인해 정정본 또는 공식 mapping을 요청드립니다.

### 1. Challenge 이미지 기동 결함

공식 스켈레톤으로 이미지를 새로 빌드한 뒤 L1, L2, L3 challenge container를 실행하면 Team 1과
Team 2의 layer container 6개가 동일하게 restart loop에 들어갑니다. gunicorn의 gevent worker import
과정에서 다음 비민감 오류 fingerprint가 발생합니다.

```text
ModuleNotFoundError: No module named 'packaging'
```

세 이미지 안에서 모듈 존재 여부를 독립 확인한 결과는 모두 동일했습니다.

```text
architecture=x86_64 gunicorn=true gevent=true packaging=false
```

공식 challenge Dockerfile은 `flask gunicorn gevent`를 설치하고 gevent worker로 gunicorn을 실행하지만
`packaging`은 명시하지 않습니다. 확인한 Dockerfile SHA-256은 다음과 같습니다.

| 파일 | SHA-256 |
|---|---|
| `deploy/challenges/layer-1/Dockerfile` | `A0E5AB484FC733E2BACB07E65231EB4DB28528E961D824E8742DD0ADBD1F64F3` |
| `deploy/challenges/layer-2/Dockerfile` | `D208B0C0AE6BB2D8EB030B1BD5EC9F28BFA3FBC7FBF25F8729DE6F7172DDCB1F` |
| `deploy/challenges/layer-3/Dockerfile` | `81BC83F1AF169EBB21257B3E96E51D47750A38FE13D698D9922D4E7459CD1DEC` |

요청 사항:

1. corrected skeleton 또는 challenge image digest를 제공해 주십시오.
2. `packaging` 명시 추가 또는 gunicorn/gevent의 known-good version pin 중 공식 수정 방식을 알려주십시오.
3. corrected artifact가 본선 실행 환경과 동일한지 확인해 주십시오.

### 2. Round mapping 충돌

최신 본선 안내는 4개 Phase, 총 14개 Round를 `P1=2`, `P2=4`, `P3=4`, `P4=4`로 정의합니다.
반면 제공된 capture/log 파일명은 다음 라벨을 사용합니다.

- P1: R1–R6
- P2: R7–R12
- P3: R13–R18
- P4/L4: 제공 자료 없음

파일 생성 시각은 10분 단위 evidence export와 일치하지만, 파일명 라벨을 공식 Round 번호로 해석하면
14 Round 일정과 모순됩니다.

요청 사항:

1. capture/log filename의 Phase·Round가 경기 Round인지 export sequence인지 확인해 주십시오.
2. 공식 Round ↔ evidence filename export manifest를 제공해 주십시오.
3. P4/L4 capture/log의 제공 여부와 canonical naming을 알려주십시오.

## 검증 영향

- 공식 Linux Broker의 관측된 ACCEPT 경로는 정상 동작했습니다. 36개 verdict의 send E2E p99/max는
  552.070 us였고, Router 누적은 46 forwarded/46 ACCEPT/0 DROP/0 GC drop이었습니다.
- 병합 후보 재검증에서도 35개 verdict의 send E2E p99/max는 530.152 us였고, Router snapshot은
  63 forwarded/63 ACCEPT/0 DROP/0 GC drop이었습니다.
- Router 강제 재시작 후 Defender는 두 차례 모두 `broker-eof`를 감지하고 각각 0.751초, 0.752초
  안에 새 session을 수립했습니다.
- 공격자 Docker stop은 두 차례 모두 signum 15 audit 뒤 exit 0, OOM=false였습니다.
- challenge 서비스가 기동하지 않아 실제 exploit delivery, flag 획득, DROP verdict, 서비스 SLA 효과는
  검증할 수 없었습니다.
- P4/L4 evidence가 없어 해당 runtime 전략이나 ACTIVE 방어 규칙은 추가하지 않았습니다.

## 재현 절차

```powershell
pwsh -NoProfile -File integration/run-with-skeleton.ps1 -SkeletonPath <official-skeleton-root>
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
docker logs <layer-container> --tail 80
docker run --rm --entrypoint python <layer-image> -c `
  "import importlib.util,platform; print(platform.machine(), bool(importlib.util.find_spec('gunicorn')), bool(importlib.util.find_spec('gevent')), bool(importlib.util.find_spec('packaging')))"
pwsh -NoProfile -File integration/run-with-skeleton.ps1 -SkeletonPath <official-skeleton-root> -Down
```

상세 비식별 Evidence inventory와 상관분석은
`docs/reviews/2026-08-20-capture-log-forensics.md`에 있습니다.
