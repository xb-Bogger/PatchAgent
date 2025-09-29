import re
from pathlib import Path
from typing import Any, List, Optional, Tuple

from patchagent.logger import logger
from patchagent.parser.cwe import CWE, CWE_DESCRIPTIONS, CWE_REPAIR_ADVICE
from patchagent.parser.sanitizer import Sanitizer, SanitizerReport
from patchagent.parser.utils import jvm_simplify_and_extract_stacktraces

# 解析 Jazzer 运行时产生的 Java 异常输出，生成结构化的 JazzerReport

JazzerSanitizerPattern = r"(== Java Exception: com\.code_intelligence\.jazzer.api\.FuzzerSecurityIssue.*)"
JavaExceptionPattern = r"(== Java Exception:.*)"

cwe_pattern_map = {
    CWE.Stack_overflow: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueLow:( )*Stack overflow.*",
    CWE.Out_of_memory: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueLow:( )*Out of memory.*",
    CWE.File_path_traversal: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueCritical:( )*File path traversal.*",
    CWE.LDAP_injection: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueCritical:( )*LDAP Injection.*",
    CWE.Naming_context_lookup: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueCritical:( )*Remote JNDI Lookup.*",
    CWE.OS_command_injection: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueCritical:( )*OS Command Injection.*",
    CWE.Reflective_call: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueHigh:( )*load arbitrary library.*",
    CWE.Remote_code_execution: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueHigh:( )*Remote Code Execution.*",
    CWE.Regular_expression_injection: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueLow:( )*Regular Expression Injection.*",
    CWE.Script_engine_injection: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueCritical:( )*Script Engine Injection.*",
    CWE.Server_side_request_forgery: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueMedium:( )*Server Side Request Forgery \(SSRF\).*",
    CWE.SQL_injection: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueHigh:( )*SQL Injection.*",
    CWE.XPath_injection: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueHigh:( )*XPath Injection.*",
}

StackTracePattern = r"at (.*)\((.*):(\d+)\)"
'''用 JavaExceptionPattern 抓取异常块（DOTALL）。
若内容匹配 JazzerSanitizerPattern，则遍历 cwe_pattern_map 命中具体 CWE；否则作为 Java_generic_exception 处理。
对 Stack_overflow 开启 handle_cyclic 以处理循环栈。
未命中任何模式时，返回 CWE.UNKNOWN 并记录错误日志。'''

class JazzerReport(SanitizerReport):
    def __init__(
        self,
        sanitizer: Sanitizer,
        content: str,
        cwe: CWE,
        stacktraces: List[List[Tuple[str, Path, int, int]]],
        purified_content: str = "",
    ):
        super().__init__(sanitizer, content, cwe, stacktraces)
        self.purified_content = purified_content

    @staticmethod
    def parse(raw_content: str, source_path: Optional[Path] = None, *args: Any, **kwargs: Any) -> Optional["JazzerReport"]:
        match = re.search(JavaExceptionPattern, raw_content, re.DOTALL)
        if match is None:
            return None

        content = match.group(1)
        lines: List[str] = []
        for line in content.splitlines():
            if line.startswith("SCARINESS") or line.startswith("DEDUP_TOKEN"):
                continue
            if line.strip() == "== libFuzzer crashing input ==":
                break
            lines.append(line)

        if re.match(JazzerSanitizerPattern, content):
            for cwe, pattern in cwe_pattern_map.items():
                if re.search(pattern, content):
                    body, stacktraces = jvm_simplify_and_extract_stacktraces(
                        lines,
                        source_path=source_path,
                        handle_cyclic=cwe is CWE.Stack_overflow,
                    )
                    return JazzerReport(Sanitizer.JazzerSanitizer, content, cwe, stacktraces, body)
        else:
            body, stacktraces = jvm_simplify_and_extract_stacktraces(lines, source_path=source_path)
            return JazzerReport(Sanitizer.JazzerSanitizer, content, CWE.Java_generic_exception, stacktraces, body)

        logger.error(f"[❌] Unknown Jazzer report: {content}")
        return JazzerReport(Sanitizer.JazzerSanitizer, content, CWE.UNKNOWN, [])
    # 提供 summary 属性，拼接 CWE 描述与修复建议
    @property
    def summary(self) -> str:
        if self.cwe is CWE.UNKNOWN:
            return self.content

        summary = (
            f"The sanitizer detected a {self.cwe.value} vulnerability."
            f"The explanation of the vulnerability is: {CWE_DESCRIPTIONS[self.cwe]}."
            f"Here is the detail: \n\n{self.purified_content}\n\n"
            f"To fix this issue, follow the advice below:\n\n{CWE_REPAIR_ADVICE[self.cwe]}"
        )

        return summary
