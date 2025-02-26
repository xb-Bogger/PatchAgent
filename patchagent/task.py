import subprocess
from functools import cached_property
from pathlib import Path
from typing import Callable, Generator, List, Optional

from patchagent.agent.base import BaseAgent
from patchagent.builder import Builder
from patchagent.context import Context
from patchagent.parser import SanitizerReport


class PatchTask:
    def __init__(
        self,
        poc_paths: List[Path],
        harness_name: str,
        builder: Builder,
    ):
        self.poc_paths: List[Path] = poc_paths
        self.harness_name: str = harness_name
        self.builder: Builder = builder
        self.project: str = self.builder.project
        self.contexts: List[Context] = []

    @cached_property
    def report(self) -> Optional[SanitizerReport]:
        try:
            for poc_path in self.poc_paths:
                if (result := self.builder.replay(self.harness_name, poc_path)) is not None:
                    return result
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None

    @property
    def patch(self) -> Optional[str]:
        if len(self.contexts) > 0:
            return self.contexts[-1].patch

    @property
    def current_context(self) -> Context:
        return self.contexts[-1]

    def new_context(self) -> Context:
        context = Context()
        self.contexts.append(context)
        return context

    def validate(self, patch: str = "") -> tuple[bool, str, str]:
        try:
            patch = self.builder.format_patch(patch)
        except subprocess.CalledProcessError:
            return False, patch, "Invalid patch format"

        try:
            self.builder.build(patch)
        except subprocess.CalledProcessError:
            return False, patch, "Build failed"
        except subprocess.TimeoutExpired:
            return False, patch, "Build timeout"

        try:
            for poc_path in self.poc_paths:
                report = self.builder.replay(self.harness_name, poc_path, patch)
                if report is not None:
                    return False, patch, report.summary
        except subprocess.CalledProcessError:
            return False, patch, "Replay failed"
        except subprocess.TimeoutExpired:
            return False, patch, "Replay timeout"

        return True, patch, ""

    def repair(self, agent_generator: Generator[BaseAgent, None, None], stop_indicator: Optional[Callable[[], bool]] = None) -> Optional[str]:
        for agent in agent_generator:
            agent.apply()
            if self.patch is not None:
                return self.patch
            if stop_indicator is not None and stop_indicator():
                return None
