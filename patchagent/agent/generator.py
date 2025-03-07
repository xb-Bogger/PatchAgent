import random
from typing import Generator

from patchagent.agent.clike.common import CommonCLikeAgent
from patchagent.agent.java.common import CommonJavaAgent
from patchagent.lang import Lang
from patchagent.task import PatchTask


def _create_agent_generator(agent_class, patchtask: PatchTask, model: str, fast: bool = False) -> Generator:
    # HACK: For some model do not need temperature
    # we temporarily rely on LiteLLM to handle this.

    kwargs = {}
    if fast:
        kwargs["auto_hint"] = random.choice([True, False])
        kwargs["counterexample_num"] = 0
        kwargs["max_iterations"] = 15
        kwargs["temperature"] = random.random()
        yield agent_class(patchtask, model=model, **kwargs)
    else:
        for counterexample_num in [0, 3]:
            for temperature in [0, 0.3, 0.7, 1]:
                for auto_hint in [True, False]:
                    kwargs["auto_hint"] = auto_hint
                    kwargs["counterexample_num"] = counterexample_num
                    kwargs["temperature"] = temperature
                    yield agent_class(patchtask, model=model, **kwargs)


def agent_generator(patchtask: PatchTask, model: str = "gpt-4o", fast: bool = False) -> Generator:
    match patchtask.builder.language:
        case Lang.CLIKE:
            return _create_agent_generator(CommonCLikeAgent, patchtask, model, fast)
        case Lang.JVM:
            return _create_agent_generator(CommonJavaAgent, patchtask, model, fast)
