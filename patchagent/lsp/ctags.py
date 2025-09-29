import subprocess
from functools import cached_property
from pathlib import Path
from typing import Dict, List, Optional

from patchagent.logger import logger
from patchagent.lsp.language import LanguageServer
from patchagent.utils import subprocess_none_pipe

# 实现一个基于 ctags 的轻量级“语言服务”（CtagsServer），用于为 C/C++ 源码快速提供符号定位索引，作为 LSP 的补充能力
# 与 ClangdServer 组合成 HybridCServer：ctags 负责全局符号索引/快速定位，clangd 负责精确语义（定义/悬停/诊断）

class CtagsServer(LanguageServer):
    def __init__(self, source_path: Path):
        super().__init__(source_path)

    @cached_property
    def symbol_map(self) -> Dict:
        # 启动外部命令 ctags，在源码根生成 tags 文件
        tagfile = self.source_path / "tags"

        subprocess.check_call(
            ["ctags", "--excmd=number", "--exclude=Makefile", "-f", tagfile, "-R"],
            cwd=self.source_path,
            stdin=subprocess.DEVNULL,
            stdout=subprocess_none_pipe(),
            stderr=subprocess_none_pipe(),
        )

        assert tagfile.is_file(), "Failed to generate ctags"
        # 解析 tags 文件，构建 symbol_map: 符号名 → [file:line,...] 的位置列表
        symbol_map: Dict[str, List[str]] = {}
        with tagfile.open("r", errors="ignore") as f:
            for text in f.readlines():
                try:
                    if text.startswith("!_TAG_"):
                        continue
                    symbol, path, line_info = text.split(';"')[0].split("\t")
                    if symbol not in symbol_map:
                        symbol_map[symbol] = []
                    symbol_map[symbol].append(f"{path}:{line_info}")
                except ValueError as e:
                    logger.warning(f"[🚧] ctag error: {e}, text: {text}")

        return symbol_map
    # 返回符号的所有候选位置
    def locate_symbol(self, symbol: str) -> List[str]:
        return self.symbol_map.get(symbol, [])

    def find_definition(self, path: Path, line: int, column: int) -> List[str]:
        return []

    def hover(self, path: Path, line: int, column: int) -> Optional[str]:
        return None
