# 방어 에이전트 이미지. 표준 라이브러리 전용 — pip install 없음.
# 이미지 시작 시간이 라운드 시간에 포함되므로 시작 경로를 짧게 유지한다.
FROM python:3.12-slim
ARG VCS_REF=unknown
LABEL org.opencontainers.image.revision=$VCS_REF

WORKDIR /app

# 판정 코드와 versioned PolicyBundle. policy/ 는 host volume 이나 런타임 다운로드가
# 아니라 build context 에 포함한다(설계 §10.2).
#
# RuntimeConfig._default_policy_dir() 는 패키지(/app/aegis_defender)에서
# ../../policy 를 보므로 컨테이너에서는 /policy 이다. /app/policy 에 복사하면
# active.json 을 찾지 못해 policy_source=empty 가 된다.
COPY src/aegis_defender /app/aegis_defender
COPY policy /policy

# Python import가 Broker 연결보다 먼저 실행되므로 build 시 bytecode를 만들어
# container startup의 fail-open 창을 줄인다. runtime policy·verdict 의미는 바꾸지 않는다.
RUN python -m compileall -q -f /app/aegis_defender

# 레퍼런스 이미지와 동일하게 비특권 사용자로 실행한다.
USER 65534

# 주소·토큰·키는 이미지에 넣지 않고 운영진이 주입하는 환경변수로만 참조한다
# (운영세칙 제7·16조). 방어 에이전트에 주입되는 환경변수는 AGENT_SOCKET,
# LLM_BASE_URL, LLM_API_KEY 셋뿐이며 PHASE·LAYER·ROUND·TEAM_ID 를 요구하지 않는다.
#
# 실행 전제(운영세칙 제16조 1항):
#   --cap-drop ALL --security-opt no-new-privileges
#   --memory-reservation 2g --cpu-shares 2048 --pids-limit 512
#   -v <router-path>/agent.sock:/run/agent.sock
#   --add-host litellm.lig.internal:<addr>
CMD ["python", "-u", "-m", "aegis_defender"]
