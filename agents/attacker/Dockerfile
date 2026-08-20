# 공격 에이전트 이미지. 표준 라이브러리 전용 — pip install 없음.
# 이미지 시작 시간이 라운드 시간에 포함되므로 시작 경로를 짧게 유지한다(integration/README).
FROM python:3.12-slim
ARG VCS_REF=unknown
LABEL org.opencontainers.image.revision=$VCS_REF

WORKDIR /app
COPY src/aegis_attacker /app/aegis_attacker
# Round 시작 직후의 known-service fast path를 늦추는 import 비용만 줄인다.
# request 순서·rate limit·공격 전략은 변경하지 않는다.
RUN python -m compileall -q -f /app/aegis_attacker
# 주소·토큰·키는 이미지에 넣지 않고 운영진이 주입하는 환경변수로만 참조한다(운영세칙 제7·16조).
CMD ["python", "-u", "-m", "aegis_attacker"]
