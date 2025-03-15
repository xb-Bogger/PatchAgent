import subprocess
from enum import Enum
from functools import cached_property
from pathlib import Path
from typing import Callable, Generator, List, Optional, Tuple

from patchagent.agent.base import BaseAgent
from patchagent.builder import Builder
from patchagent.context import Context
from patchagent.parser import SanitizerReport


class ValidationResult(Enum):
    Success = "Success"
    InvalidPatchFormat = "Invalid patch format"
    BuildFailed = "Build failed"
    BuildTimeout = "Build timeout"
    DetectedBug = "Detected bug"
    ReplayFailed = "Replay failed"
    ReplayTimeout = "Replay timeout"
    FunctionTestFailed = "Function test failed"
    FunctionTestTimeout = "Function test timeout"


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

    def validate(self, patch: str = "", function_test: bool = True) -> Tuple[ValidationResult, str, str]:
        try:
            patch = self.builder.format_patch(patch)
        except subprocess.CalledProcessError:
            return ValidationResult.InvalidPatchFormat, patch, ValidationResult.InvalidPatchFormat.value

        try:
            self.builder.build(patch)
        except subprocess.CalledProcessError:
            return ValidationResult.BuildFailed, patch, ValidationResult.BuildFailed.value
        except subprocess.TimeoutExpired:
            return ValidationResult.BuildTimeout, patch, ValidationResult.BuildTimeout.value

        try:
            for poc_path in self.poc_paths:
                report = self.builder.replay(self.harness_name, poc_path, patch)
                if report is not None:
                    return ValidationResult.DetectedBug, patch, report.summary
        except subprocess.CalledProcessError:
            return ValidationResult.ReplayFailed, patch, ValidationResult.ReplayFailed.value
        except subprocess.TimeoutExpired:
            return ValidationResult.ReplayTimeout, patch, ValidationResult.ReplayTimeout.value

        if function_test:
            try:
                if self.builder.function_test(patch) is False:
                    return ValidationResult.FunctionTestFailed, patch, ValidationResult.FunctionTestFailed.value
            except subprocess.CalledProcessError:
                return ValidationResult.FunctionTestFailed, patch, ValidationResult.FunctionTestFailed.value
            except subprocess.TimeoutExpired:
                return ValidationResult.FunctionTestTimeout, patch, ValidationResult.FunctionTestTimeout.value

        return ValidationResult.Success, patch, ValidationResult.Success.value

    def repair(self, agent_generator: Callable[["PatchTask"], Generator[BaseAgent, None, None]]) -> Optional[str]:
        for agent in agent_generator(self):
            agent.apply()
            if self.patch is not None:
                return self.patch
