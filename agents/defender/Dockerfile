# 방어 에이전트 이미지 — **초안. Docker 담당자와 팀장 이경준의 검토가 필요하다.**
#
# 설계 §14: "실제 dependency와 entrypoint는 Docker 담당자와 검토하되 Dockerfile은
# 방어 담당자가 단독 확정하지 않는다." 이 파일은 §17.1의 인계 항목(실행 명령,
# 환경변수, 런타임 의존성, socket mount 요구사항)을 구체적인 형태로 전달하기 위한
# 초안이며, 확정 권한은 Docker 담당자에게 있다.
#
# 표준 라이브러리 전용 — pip install 없음(requirements.txt 참조).
# 이미지 시작 시간이 Round 시간에 포함되므로 시작 경로를 짧게 유지한다.
FROM python:3.12-slim
WORKDIR /app

# 판정 코드와 versioned PolicyBundle. policy/ 는 host volume 이나 런타임 다운로드가
# 아니라 build context 에 포함한다(설계 §10.2).
COPY src/aegis_defender /app/aegis_defender
COPY policy /app/policy

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
