from typing import Optional

from patchagent.logger import log


class AgentStopException(Exception):
    pass


class PatchFoundException(Exception):
    pass


class BaseAgent:
    def __call__(self) -> Optional[str]:
        try:
            return self.apply()
        except AgentStopException as e:
            log.info(f"[🛑] Agent stopped because {e}")
        except PatchFoundException as e:
            log.info("[🎉] Patch is found")
            return str(e)

    def apply(self):
        raise NotImplementedError
