# Agents

본선에 제출할 두 개의 독립 Docker 이미지가 위치할 영역입니다.

- `attacker/`: 정찰, 계획, 실행, 플래그 수집·제출
- `defender/`: Broker 연결, 패킷 해석, 300ms 내 ACCEPT/DROP 판정

두 에이전트는 런타임 패키지나 메모리를 공유하지 않습니다. 공통으로 지켜야 하는 형식만 `../contracts/`에서 관리합니다.
