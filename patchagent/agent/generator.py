import random
from typing import Generator

from patchagent.agent.clike.openai import OpenAICLikeAgent
from patchagent.agent.java.openai import OpenAIJavaAgent
from patchagent.lang import Lang
from patchagent.task import PatchTask


def fast_clike_agent_generator(patchtask: PatchTask, model: str = "gpt-4o") -> Generator:
    yield OpenAICLikeAgent(
        patchtask,
        model=model,
        temperature=random.random(),
        auto_hint=random.choice([True, False]),
        counterexample_num=0,
        max_iterations=15,
    )


def fast_java_agent_generator(patchtask: PatchTask, model: str = "gpt-4o") -> Generator:
    yield OpenAIJavaAgent(
        patchtask,
        model=model,
        temperature=random.random(),
        auto_hint=random.choice([True, False]),
        counterexample_num=0,
        max_iterations=15,
    )


def clike_agent_generator(patchtask: PatchTask, model: str = "gpt-4o") -> Generator:
    for counterexample_num in [0, 3]:
        for temperature in [0 / 3, 1 / 3, 2 / 3, 3 / 3]:
            for auto_hint in [True, False]:
                yield OpenAICLikeAgent(
                    patchtask,
                    model=model,
                    temperature=temperature,
                    auto_hint=auto_hint,
                    counterexample_num=counterexample_num,
                )


def java_agent_generator(patchtask: PatchTask, model: str = "gpt-4o") -> Generator:
    for counterexample_num in [0, 3]:
        for temperature in [0 / 3, 1 / 3, 2 / 3, 3 / 3]:
            for auto_hint in [True, False]:
                yield OpenAIJavaAgent(
                    patchtask,
                    model=model,
                    temperature=temperature,
                    auto_hint=auto_hint,
                    counterexample_num=counterexample_num,
                )


def generic_agent_generator(patchtask: PatchTask, model: str = "gpt-4o") -> Generator:
    match patchtask.builder.language:
        case Lang.CLIKE:
            return clike_agent_generator(patchtask, model)
        case Lang.JVM:
            return java_agent_generator(patchtask, model)


def fast_agent_generator(patchtask: PatchTask, model: str = "gpt-4o") -> Generator:
    match patchtask.builder.language:
        case Lang.CLIKE:
            return fast_clike_agent_generator(patchtask, model)
        case Lang.JVM:
            return fast_java_agent_generator(patchtask, model)
