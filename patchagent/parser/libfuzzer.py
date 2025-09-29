import re
from pathlib import Path
from typing import Any, List, Optional, Tuple

from patchagent.parser.cwe import CWE
from patchagent.parser.sanitizer import Sanitizer, SanitizerReport
from patchagent.parser.utils import (
    classic_simplify_and_extract_stacktraces,
    jvm_simplify_and_extract_stacktraces,
    remove_ansi_escape,
)

# 解析 libFuzzer 的崩溃输出，结构化为 LibFuzzerReport，供上层汇总与定位

LibFuzzerPattern = r"(==\d+== ERROR: libFuzzer: .+)"
'''匹配与清洗
去除 ANSI 转义后，用正则捕获首个 “==<pid>== ERROR: libFuzzer: …” 段。
过滤无关行（SCARINESS/DEDUP_TOKEN），在 SUMMARY 前截断正文。
调用栈提取
先用 classic_simplify_and_extract_stacktraces（C/C++ 风格）解析；若为空，回退 jvm_simplify_and_extract_stacktraces（Java 栈）。
输出
返回 Sanitizer.LibFuzzer，CWE 固定为 CWE.Libfuzzer；summary 直接输出净化后的正文。'''

class LibFuzzerReport(SanitizerReport):
    def __init__(
        self,
        content: str,
        cwe: CWE,
        stacktraces: List[List[Tuple[str, Path, int, int]]],
        purified_content: str,
    ):

        super().__init__(Sanitizer.LibFuzzer, content, cwe, stacktraces)
        self.purified_content = purified_content

    @staticmethod
    def parse(raw_content: str, source_path: Optional[Path] = None, work_path: Optional[Path] = None, *args: Any, **kwargs: Any) -> Optional["LibFuzzerReport"]:
        raw_content = remove_ansi_escape(raw_content)
        match = re.search(LibFuzzerPattern, raw_content, re.DOTALL)
        if match is None:
            return None

        content = match.group(1)
        body = []
        for line in content.splitlines():
            if line.startswith("SCARINESS") or line.startswith("DEDUP_TOKEN"):
                continue
            if line.startswith("SUMMARY:"):
                break
            body.append(line)

        simplified, stacktraces = classic_simplify_and_extract_stacktraces(body, source_path, work_path)

        if len(stacktraces) == 0:
            simplified, stacktraces = jvm_simplify_and_extract_stacktraces(body, source_path, work_path)

        return LibFuzzerReport(content, CWE.Libfuzzer, stacktraces, simplified)

    @property
    def summary(self) -> str:
        return f"The libFuzzer report is:\n\n{self.purified_content}"
