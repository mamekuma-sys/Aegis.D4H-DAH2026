# 규칙 및 인터페이스 체크리스트

## 자료별 용도

| 자료 | 사용하는 내용 | 사용하지 않는 내용 |
|---|---|---|
| 예선 안내서 | 예선 평가 목적, 제출물 범위, 평가 항목 | 본선 실행 인터페이스 추정 |
| 예선 보고서 | A1~A5, S1~S5, 상관분석, 가용성 우선 원칙 | 합성 지표를 본선 성능으로 주장 |
| 예선 소스 | 검증된 스키마·상관분석 아이디어와 테스트 | `AttackSimulationAgent`를 실제 공격기로 사용 |
| 본선 운영세칙 | 14절의 제출 이미지, 15절의 pull·라운드 생명주기, 16절의 컨테이너 실행 옵션을 포함한 본선 운영 기준 | 예선 구현과의 동일성 의무를 임의로 추가 |
| 공식 agent guide | 환경변수, 제출 API, Broker 프레임, 시간 계약 | 데모 취약점을 본선 취약점으로 간주 |
| 파생 팀 메모 | 공식 원본과 실제 인터페이스를 찾기 위한 이해 보조 | `FINALS-DAY-NOTE`나 `SKELETON-EXPLANATION`을 공식 원본 또는 독립 근거로 인용 |

`FINALS-DAY-NOTE`와 `SKELETON-EXPLANATION`은 파생 팀 메모입니다. 최신 운영진의 직접 안내와 같은 권위를 갖지 않으며, 충돌 시 운영진 직접 안내와 `FINALS-RULES`, 공식 agent guide, 실제 스켈레톤이 우선합니다.

## 현재 고정된 본선 계약

### 공통

- 공격·방어는 각각 독립 Docker 이미지입니다.
- 컨테이너의 외부 인터넷 연결은 제한되며 대회 LiteLLM Proxy를 사용합니다.
- 소스·모델·API 사용 증빙을 요청받을 수 있으므로 변경 근거를 보존합니다.
- 컨테이너와 flag는 라운드마다 초기화되므로 런타임 상태를 영속 상태로 간주하지 않습니다.
- DoS, 운영 범위 밖 접근, 운영망 침범, rate limit 우회, flag 획득 목적 밖의 파괴·변조를 금지합니다.
- 동점 시 LLM 토큰 비용이 사용되므로 호출 예산과 사용 증빙을 관리합니다.

### 공격

- `TARGETS`, `PORTS`, `SUBMIT_URL`, `SUBMIT_TOKEN`을 환경변수로 받습니다.
- 대상은 `TARGETS × PORTS` 조합이며 주소와 포트를 하드코딩하지 않습니다.
- 플래그는 제출 API에 JSON으로 전송합니다.
- 제출 결과와 HTTP 429 rate limit을 처리합니다.
- 상대 방어망 접근 한도는 공격 에이전트당 초당 10회, 버스트 20입니다.
- flag 제출 한도는 분당 30회이며 HTTP 429에 backoff를 적용합니다.
- 허용된 팀 진입점, 대회 LiteLLM Proxy, 제출 서버 외부로 요청하지 않습니다.

### 방어

- `AGENT_SOCKET`에서 `AF_UNIX`/`SOCK_SEQPACKET`으로 Broker에 연결합니다.
- `PACKET(0x01)`을 받고 300ms 안에 `VERDICT(0x02)`를 반환합니다.
- verdict는 `ACCEPT(0x00)` 또는 `DROP(0x01)`입니다.
- 약 1초마다 `HEARTBEAT(0x05)`를 보냅니다.
- 원격 LLM 호출을 패킷별 동기 hot path에 넣지 않습니다.
- NAT가 소스 IP를 정규화하므로 소스 IP만으로 공격자를 식별하지 않습니다.
- 각 레이어에는 30ms 지연과 0.3% 패킷 손실이 모사됩니다.
- 방어 에이전트가 없거나 죽으면 Broker는 fail-open으로 동작하고, verdict가 300ms를 넘으면 해당 패킷은 DROP됩니다.

### 이미지 운영

- `FINALS-RULES` 14절에 따라 공격·방어 이미지는 각각 `ligacr.azurecr.io/team{N}/attacker:latest`, `ligacr.azurecr.io/team{N}/defender:latest`를 사용합니다.
- `FINALS-RULES` 15절에 따라 `latest` 이미지는 라운드 시작 5분 전에 pull되며 pull timeout은 20분입니다.
- `FINALS-RULES` 15절에 따라 컨테이너는 라운드마다 새로 생성되고 종료 후 삭제되며 시작 시간도 라운드 시간에 포함됩니다.
- `FINALS-RULES` 16절에 따라 공통으로 `no-new-privileges`, memory reservation `2g`, CPU shares `2048`, PID limit `512`를 적용합니다.
- `FINALS-RULES` 16절에 따라 방어 컨테이너는 `cap-drop ALL`과 Broker socket mount를 적용하고, 운영 환경변수는 실행 시 주입합니다.
- `OFFICIAL-SKELETON`과 공식 agent guide 검증은 Compose, mount, 환경변수 주입 구현이 16절과 최신 운영진 직접 안내에 맞는지 확인하는 절차입니다.

## 아직 가정하면 안 되는 내용

- 본선 표적이 예선 S1~S5 취약점을 그대로 포함한다는 보장
- 방어 에이전트가 차량 상태, 미션 의미, 파라미터 해시나 물리 상태를 직접 받는다는 가정
- 공식 계약에 없는 RTL, 롤백 또는 기체 제어 권한
- 로컬 데모 챌린지의 SSRF, 세션 변조, SQLi가 본선에 동일하게 등장한다는 가정

## 변경 관리

운영진의 새 직접 안내가 이 체크리스트와 다르면 새 안내가 우선합니다. 파생 팀 메모를 운영진 직접 안내로 취급하지 않습니다. 팀장은 원본 인벤토리, 이 체크리스트, `contracts/`와 관련 테스트를 같은 PR에서 갱신하거나 변경 순서를 PR 본문에 명시합니다. 공식 스켈레톤 파일은 이 저장소 밖에 유지합니다.
