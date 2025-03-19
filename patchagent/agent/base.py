from typing import Optional

from patchagent.logger import logger


class AgentStopException(Exception): ...


class PatchFoundException(Exception): ...


class BaseAgent:
    def __call__(self) -> Optional[str]:
        try:
            return self.apply()
        except AgentStopException as e:
            logger.info(f"[🛑] Agent stopped because {e}")
        except PatchFoundException as e:
            logger.info("[🎉] Patch is found")
            return str(e)

    def apply(self):
        raise NotImplementedError
