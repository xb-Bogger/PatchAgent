import shutil
import tempfile
from functools import cached_property
from pathlib import Path
from typing import Optional

from git import Repo

from patchagent.builder.utils import BuilderProcessError, safe_subprocess_run
from patchagent.lang import Lang
from patchagent.logger import logger
from patchagent.lsp.language import LanguageServer
from patchagent.parser import SanitizerReport

'''实现通用构建器抽象（Builder 基类）+ PoC 占位类型。为具体语言子类（C/C++、Java 等）提供统一的源码准备、补丁应用、补丁格式化、仓库隔离、语言探测接口'''
class PoC:
    def __init__(self) -> None: ...


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
        # 先清空workspace再创建
        if clean_up:
            shutil.rmtree(self.workspace, ignore_errors=True)
        self.workspace.mkdir(parents=True, exist_ok=True)

    @cached_property
    def source_path(self) -> Path:
        target_path = self.workspace / "immutable" / self.org_source_path.name
        if not target_path.is_dir():
            # 保留符号链接
            shutil.copytree(self.org_source_path, target_path, symlinks=True)

        return target_path

    @cached_property
    def source_repo(self) -> Repo:
        # 删除内部已有.git目录后git init
        target_path = self.workspace / "git" / self.org_source_path.name
        if not target_path.is_dir():
            shutil.copytree(self.source_path, target_path, symlinks=True)

        if (target_path / ".git").is_dir():
            shutil.rmtree(target_path / ".git")

        repo = Repo.init(target_path)

        # This is a workaround to prevent repo.index.add from altering file permissions
        # when files are added to the Git index
        # 建立基线快照
        repo.git.add(repo.untracked_files)
        repo.index.commit("Initial commit")
        return repo

    @cached_property
    def language(self) -> Lang:
        raise NotImplementedError("language not implemented")

    @cached_property
    def language_server(self) -> LanguageServer:
        raise NotImplementedError("language_server not implemented")

    # 清理工作副本，通过 git apply 验证补丁语法/上下文
    def check_patch(self, patch: str) -> None:
        logger.info("[🔍] Checking patch")

        self.source_repo.git.reset("--hard")
        self.source_repo.git.clean("-fdx")

        safe_subprocess_run(
            ["git", "apply"],  # empty patch is not allowed
            Path(self.source_repo.working_dir),
            input=patch.encode(),
        )

    # 把用户/LLM 生成的“近似补丁”格式化成规范 diff
    def format_patch(self, patch: str) -> Optional[str]:
        logger.info("[🩹] Formatting patch")

        self.source_repo.git.reset("--hard")
        self.source_repo.git.clean("-fdx")

        try:
            safe_subprocess_run(
                ["patch", "-F", "3", "--no-backup-if-mismatch", "-p1"],
                Path(self.source_repo.working_dir),
                input=patch.encode(),
            )

            return safe_subprocess_run(["git", "diff"], Path(self.source_repo.working_dir)).decode(errors="ignore")
        except BuilderProcessError:
            return None
    # 编译
    def build(self, patch: str = "") -> None:
        raise NotImplementedError("build not implemented")
    # 运行POC触发
    def replay(self, poc: PoC, patch: str = "") -> Optional[SanitizerReport]:
        raise NotImplementedError("replay not implemented")
    # 功能回归测试
    def function_test(self, patch: str = "") -> None: ...
