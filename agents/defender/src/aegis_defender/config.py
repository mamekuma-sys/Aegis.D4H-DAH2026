"""환경변수 검증과 안전한 기본값 (`RuntimeConfig`).

설계 §7 구성요소 경계, §16.1 하나의 누적 적응형 런타임.

공식 계약(운영세칙 제16조 2항)상 방어 에이전트에 주입되는 환경변수는
`AGENT_SOCKET`, `LLM_BASE_URL`, `LLM_API_KEY` 셋뿐이다. 따라서 이 모듈은
`PHASE`, `LAYER`, `ROUND`, `TEAM_ID`, `PORTS`를 **읽지 않는다**. 열려 있어야 할
포트 목록을 런타임이 알 수 없다는 사실이 §9.2의 "포트 게이트는 관측 기반"
결정의 근거다.

주소·토큰·키는 소스코드에 하드코딩하지 않는다(운영세칙 제7조 2항).
"""

from __future__ import annotations

import os
import posixpath
from dataclasses import dataclass
from typing import Mapping

DEFAULT_AGENT_SOCKET = "/run/agent.sock"
DEFAULT_LLM_BASE_URL = "http://litellm.lig.internal:4000"

# §12.1 — 팀별 쿼터가 가장 넉넉한 모델(6.5M TPM / 65K RPM). gpt-4.1-mini는 TPM이
# 크지만 RPM이 11.5K로 작아 호출 빈도가 높은 용도에 부적합하다. 당일 오리엔테이션
# 공지가 이 기본값보다 우선한다.
DEFAULT_LLM_MODEL = "gpt-4o-mini"

# 공식 계약에 없어 런타임이 요구해서는 안 되는 환경변수(§16.1). 테스트가 이 목록을
# 사용해 "설정이 이 값들에 의존하지 않는다"를 회귀 검증한다.
UNCONTRACTED_ENV_NAMES = ("PHASE", "LAYER", "ROUND", "TEAM_ID", "PORTS", "TARGETS")


class ConfigError(ValueError):
    """기동을 중단시켜야 하는 환경변수 형식 오류.

    §13 오류 표의 첫 행 — `AGENT_SOCKET` 누락·경로 없음·permission denied는
    기동 실패를 명시적 종료로 처리한다. 소켓 없이 계속 도는 프로세스는
    Broker fail-open을 숨기기만 한다.
    """


def _default_policy_dir() -> str:
    """이미지 build context에 포함된 `policy/` 디렉터리(§10.2).

    host volume이나 runtime 다운로드에 의존하지 않는다. 패키지 위치에서
    상대 경로로 찾으므로 컨테이너 WORKDIR에 영향받지 않는다.
    """
    package_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(package_dir, "..", "..", "policy"))


@dataclass(frozen=True)
class RuntimeConfig:
    agent_socket: str = DEFAULT_AGENT_SOCKET
    llm_base_url: str = DEFAULT_LLM_BASE_URL
    llm_api_key: str = ""
    llm_model: str = DEFAULT_LLM_MODEL
    policy_dir: str = ""

    @property
    def advisory_enabled(self) -> bool:
        """LLM 조언은 선택적이다(§12).

        키가 없으면 `AdvisoryWorker`를 아예 기동하지 않는다. 이는 장애가 아니라
        정상 동작이며 HEARTBEAT·verdict에 영향을 주지 않는다.
        """
        return bool(self.llm_api_key and self.llm_base_url)


def load_config(env: Mapping[str, str] | None = None) -> RuntimeConfig:
    """환경변수 매핑에서 런타임 설정을 파싱·검증한다.

    `AGENT_SOCKET`이 빈 값이면 계약 기본값 `/run/agent.sock`을 쓴다. 상대 경로는
    Broker가 mount하는 절대 경로 계약(운영세칙 제16조 1항
    `-v <router-path>/agent.sock:/run/agent.sock`)과 어긋나므로 거부한다.

    경로의 실제 존재 여부는 여기서 확인하지 않는다. Broker가 아직 소켓을 만들지
    않은 startup race는 §13에서 bounded backoff 재시도로 처리해야 하고, 기동
    시점의 부재를 종료 사유로 만들면 그 재시도 경로가 무력해지기 때문이다.
    """
    source = os.environ if env is None else env

    socket_path = (source.get("AGENT_SOCKET") or "").strip() or DEFAULT_AGENT_SOCKET
    # 컨테이너 안의 Linux 경로이므로 호스트 OS 규칙이 아니라 POSIX 규칙으로 판단한다.
    # `os.path.isabs`는 Windows에서 `ntpath`로 위임되는데, Python 3.13부터
    # `ntpath.isabs('/run/agent.sock')`가 False라서 계약 기본값이 거부된다.
    # 개발자가 Windows에서 테스트를 돌린다는 이유로 런타임 계약이 달라져서는 안 된다.
    if not posixpath.isabs(socket_path):
        raise ConfigError(f"AGENT_SOCKET 은 절대 경로여야 합니다: {socket_path!r}")

    base_url = (source.get("LLM_BASE_URL") or "").strip() or DEFAULT_LLM_BASE_URL
    base_url = base_url.rstrip("/")
    if base_url and not base_url.startswith(("http://", "https://")):
        raise ConfigError(f"LLM_BASE_URL 스킴이 올바르지 않습니다: {base_url!r}")

    policy_dir = (source.get("DEFENDER_POLICY_DIR") or "").strip() or _default_policy_dir()

    return RuntimeConfig(
        agent_socket=socket_path,
        llm_base_url=base_url,
        llm_api_key=(source.get("LLM_API_KEY") or "").strip(),
        llm_model=DEFAULT_LLM_MODEL,
        policy_dir=policy_dir,
    )
