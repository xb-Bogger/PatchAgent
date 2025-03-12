import shutil
import subprocess
import tempfile
from functools import cached_property
from pathlib import Path
from typing import Optional

from git import Repo

from patchagent.lang import Lang
from patchagent.logger import log
from patchagent.lsp.language import LanguageServer
from patchagent.parser import SanitizerReport
from patchagent.utils import subprocess_none_pipe


class Builder:
    def __init__(
        self,
        project: str,
        source_path: Path,
        workspace: Optional[Path] = None,
        clean_up: bool = True,
    ):
        self.project = project
        self.org_source_path = source_path
        self.workspace = workspace or Path(tempfile.mkdtemp())

        if clean_up:
            shutil.rmtree(self.workspace, ignore_errors=True)
        self.workspace.mkdir(parents=True, exist_ok=True)

    @cached_property
    def source_path(self) -> Path:
        target_path = self.workspace / "immutable" / self.org_source_path.name
        if not target_path.is_dir():
            shutil.copytree(self.org_source_path, target_path, symlinks=True)

        return target_path

    @cached_property
    def source_repo(self) -> Repo:
        target_path = self.workspace / "git" / self.org_source_path.name
        if not target_path.is_dir():
            shutil.copytree(self.source_path, target_path, symlinks=True)

        if (target_path / ".git").is_dir():
            shutil.rmtree(target_path / ".git")

        repo = Repo.init(target_path)
        repo.index.add(repo.untracked_files)
        repo.index.commit("Initial commit")
        return repo

    @cached_property
    def language(self) -> Lang:
        raise NotImplementedError("language not implemented")

    @cached_property
    def language_server(self) -> LanguageServer:
        raise NotImplementedError("language_server not implemented")

    def format_patch(self, patch: str) -> str:
        log.info("[🩹] Formatting patch")

        self.source_repo.git.reset("--hard", "HEAD")
        subprocess.run(
            ["patch", "-p1"],
            cwd=self.source_repo.working_dir,
            input=patch.encode(),
            stdout=subprocess_none_pipe(),
            stderr=subprocess_none_pipe(),
            check=True,
        )
        return self.source_repo.git.diff("HEAD", "--diff-filter=M")

    def build(self, patch: str) -> None:
        raise NotImplementedError("build not implemented")

    def replay(self, harness_name: str, poc_path: Path, patch: str = "") -> Optional[SanitizerReport]:
        raise NotImplementedError("run_poc not implemented")

    def function_test(self, patch: str = "") -> bool:
        return True
