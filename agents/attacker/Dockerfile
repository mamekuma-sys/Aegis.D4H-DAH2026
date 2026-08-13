# 공격 에이전트 이미지. 표준 라이브러리 전용 — pip install 없음.
# 이미지 시작 시간이 라운드 시간에 포함되므로 시작 경로를 짧게 유지한다(integration/README).
FROM python:3.12-slim
WORKDIR /app
COPY src/aegis_attacker /app/aegis_attacker
# 주소·토큰·키는 이미지에 넣지 않고 운영진이 주입하는 환경변수로만 참조한다(운영세칙 제7·16조).
CMD ["python", "-u", "-m", "aegis_attacker"]
