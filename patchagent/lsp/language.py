from pathlib import Path
from typing import List, Optional
# CtagsServer/ClangdServer/HybridCServer/JavaLanguageServer 均继承此类，实现各自的符号定位、跳转与悬停等能力
# 定义语言服务的抽象基类 LanguageServer，统一对源码根的访问与语义查询接口
class LanguageServer:
    def __init__(self, source_path: Path):
        self.source_path = source_path
    # 提供通用的源码片段读取方法 viewcode
    def viewcode(self, path: Path, start_line: int, end_line: int) -> Optional[List[str]]:
        assert not path.is_absolute()
        # 返回 List[str]（end_line 为切片上界，半开区间），文件不存在返回 None
        real_path = self.source_path / path
        if real_path.is_file():
            with real_path.open("r", errors="ignore") as f:
                return f.readlines()[start_line - 1 : end_line]

        return None

    def locate_symbol(self, symbol: str) -> List[str]:
        raise NotImplementedError

    def find_definition(self, path: Path, line: int, column: int) -> List[str]:
        raise NotImplementedError

    def hover(self, path: Path, line: int, column: int) -> Optional[str]:
        raise NotImplementedError
