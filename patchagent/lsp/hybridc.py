from pathlib import Path
from typing import List

from patchagent.lsp.clangd import ClangdServer
from patchagent.lsp.ctags import CtagsServer
from patchagent.lsp.language import LanguageServer

# 实现一个“混合式”C 语言服务 HybridCServer，把快而全的 ctags 索引与精准的 clangd 语义查询组合在一起，对外暴露统一接口

class HybridCServer(LanguageServer):
    def __init__(self, ctags_source_path: Path, clangd_source_path: Path):
        super().__init__(ctags_source_path)
        # 生成并缓存全局符号索引，支持快速符号定位
        self.ctags = CtagsServer(ctags_source_path)
        # 通过 LSP 提供精确的定义跳转与悬停信息
        self.clangd = ClangdServer(clangd_source_path)

    def locate_symbol(self, symbol: str) -> List[str]:
        return self.ctags.locate_symbol(symbol)

    def find_definition(self, path: Path, line: int, column: int) -> List[str]:
        return self.clangd.find_definition(path, line, column)

    def hover(self, path: Path, line: int, column: int) -> str:
        return self.clangd.hover(path, line, column)
