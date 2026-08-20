# 2026-08-21 본선 후보 재검증

## 판정

**NOT_READY / HOLD**를 유지한다.

- 공격자 known-proxy 회귀는 해소됐다. A1D0의 A0D0 대비 capture delta는 seed
  404–408에서 각각 `+3/+3/+3/+6/+3`이고 최악값도 `+3`이다.
- 방어자 startup 창은 줄었지만 strict P0는 남았다. A1D1 seed 404에서 defender
  session 연결 17ms 전에 capture 3개가 관측됐다. seed 405–408은 capture 0이다.
- 정상 트래픽은 20경기 720/720 성공했고 D1 verdict-send E2E 최댓값은
  1.822ms로 300ms 계약 이내였다.
- 사람 점수, blind holdout, 실제 L4, 공식 SLA generator는 여전히 없다.

따라서 개선 코드는 후보 브랜치에 보존하되 `main` 승격 조건은 충족하지 못한다.

## 변경 및 이미지

재검증 대상 runtime commit은 `3c9609cadc601f7e21ed544f3b04d8f1a57345c7`이다.

| ID | Linux/amd64 image digest |
|---|---|
| A1 | `sha256:99f2520b3908c357f641ddb586892bb9e686ed13c52f1a1f5084e5817d99e9e9` |
| D1 | `sha256:6affb7da905d3c9603b290adbfe0f01846273684bef0460f9e279a567b206709` |

갱신된 image manifest SHA-256은
`06db5ceca0541fd18418801d3962eac5f0158ac9f59cf6b5793797b0760800ac`이다.

- A1은 첫 bootstrap 무응답 endpoint를 30초가 아니라 1초 후 재시도한다.
- A1 종료 요청은 signal handler에서 playbook lock을 잡지 않고 worker가 stop event를
  polling하도록 바뀌었다.
- D1은 최초 Broker attach 동안 2ms 고정 polling을 사용하고, 재연결에는 기존 지수
  backoff를 유지한다.
- `frozen-images.json`은 위 두 digest와 runtime commit을 가리키도록 갱신했다.

## 실행 조건

- 공식 skeleton: `scripts/validate-skeleton.ps1` PASS
- matrix: A0D0/A1D0/A0D1/A1D1 × seed 404–408
- round: 10초
- 정상 요청: route당 6개
- LLM key: 비어 있음
- 결과 위치: Git 밖 OS 임시 폴더
- raw PCAP, 로그, flag, token: Git 미포함

PowerShell 7.6.5 portable archive는 공식 릴리스 SHA-256
`32eb8f6cdce08f86e987d625a2733e54ac3e289ae7e1621b14c0b5bcec2434ea`와
일치하는 것을 확인한 뒤 실행에만 사용했다.

## 결과

| Matrix | seed별 capture | 정상 실패 | candidate container 실패 |
|---|---|---:|---:|
| A0D0 | `3/3/0/0/3` | 0 | 해당 없음 |
| A1D0 | `6/6/3/6/6` | 0 | 0 |
| A0D1 | `0/0/0/0/0` | 0 | 해당 없음 |
| A1D1 | `3/0/0/0/0` | 0 | 0 |

- D1 session 연결 offset: A0D1 `406–480ms`, A1D1 `429–477ms`
- A1D1 pre-session capture seed: `1/5` (`S404`, `-17ms`)
- D1 verdict-send E2E max: `1,822.346us`
- GC DROP max: `0`
- A1/D1 LLM calls/tokens: `0/0`
- deterministic judge 필수 proxy gate: 모두 PASS
- AI weighted score: `50.0/100`
- 최종 verdict: `NOT_READY`, recommendation: `HOLD`

## 증거 hash

- matrix index SHA-256:
  `bb304eff01f7a21aec0c673a035192811de9fbffa900fd57c752ef654d57a11a`
- judgement SHA-256:
  `6ca6c6a01d253232e10f1b246c16ef7ba26c0478b481d45f3646b7c528de1895`

개별 20개 result SHA-256은 matrix index와 judgement의 evidence mapping에 포함되며,
sanitized 결과 파일은 Git 밖 팀 증거 저장소로 인계해야 한다.

## 남은 병합 게이트

1. Docker owner가 동일 digest의 Linux/Broker 재현 결과를 독립 확인한다.
2. 공격자 owner가 A1 bootstrap/cooldown 변경과 효과성 결과를 승인한다.
3. 방어자 owner와 팀장이 남은 `S404` startup 제약을 승인하거나 공식 Arena 시작
   순서로 해소됐음을 관측한다.
4. 독립 사람 점수와 blind holdout/공식 SLA 결과를 judge에 입력한다.
