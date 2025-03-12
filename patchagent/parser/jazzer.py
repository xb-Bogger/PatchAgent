import re
from pathlib import Path
from typing import List, Optional, Tuple

from patchagent.parser.cwe import CWE, CWE_DESCRIPTIONS, CWE_REPAIR_ADVICE
from patchagent.parser.sanitizer import Sanitizer, SanitizerReport
from patchagent.parser.utils import guess_relpath

JazzerSanitizerPattern = r"(== Java Exception: com\.code_intelligence\.jazzer.api\.FuzzerSecurityIssue.*)"
cwe_pattern_map = {
    CWE.Stack_overflow: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueLow: Stack overflow.*",
    CWE.Out_of_memory: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueLow: Out of memory.*",
    # NOTE: File_path_traversal have no test case
    CWE.File_path_traversal: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueCritical: File path traversal.*",
    # NOTE: LDAP_injection have no test case
    CWE.LDAP_injection: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueCritical: LDAP Injection.*",
    # NOTE: Naming_context_lookup have no test case
    CWE.Naming_context_lookup: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueCritical: Remote JNDI Lookup.*",
    # NOTE: OS_command_injection have no test case
    CWE.OS_command_injection: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueCritical: OS Command Injection.*",
    # NOTE: Path_traversal have no test case
    CWE.Reflective_call: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueHigh: load arbitrary library.*",
    CWE.Remote_code_execution: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueHigh: Remote Code Execution.*",
    CWE.Regular_expression_injection: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueLow: Regular Expression Injection.*",
    # NOTE: Script_engine_injection have no test case
    CWE.Script_engine_injection: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueCritical: Script Engine Injection.*",
    CWE.Server_side_request_forgery: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueMedium: Server Side Request Forgery \(SSRF\).*",
    # NOTE: SQL_injection have no test case
    CWE.SQL_injection: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueHigh: SQL Injection.*",
    CWE.XPath_injection: r"== Java Exception: com\.code_intelligence\.jazzer\.api\.FuzzerSecurityIssueHigh: XPath Injection.*",
}

StackTracePattern = r"at (.*)\((.*):(\d+)\)"


class JazzerReport(SanitizerReport):
    def __init__(
        self,
        sanitizer: Sanitizer,
        content: str,
        cwe: CWE,
        stacktrace: List[Tuple[str, Path, int, int]],
        purified_content: str = "",
    ):
        super().__init__(sanitizer, content, cwe, stacktrace)
        self.purified_content = purified_content

    @staticmethod
    def parse(raw_content: str, source_path: Optional[Path] = None, *args, **kwargs) -> Optional["JazzerReport"]:
        match = re.search(JazzerSanitizerPattern, raw_content, re.DOTALL)
        if match is None:
            return None

        content = match.group(1)
        for cwe, pattern in cwe_pattern_map.items():
            if re.search(pattern, content):
                stacktrace: List[Tuple[str, Path, int, int]] = []
                lines = content.splitlines()
                for line in lines:
                    match = re.search(StackTracePattern, line)
                    if match:
                        name = match.group(1)
                        classpath = name.split(".")
                        filename = Path(match.group(2))
                        linum = int(match.group(3))

                        filepath = Path("")
                        for part in classpath:
                            if part == filename.stem:
                                filepath /= filename
                                relpath = guess_relpath(source_path, filepath)
                                filepath = relpath or filepath
                                break

                            filepath /= part

                        if filepath is not None:
                            stacktrace.append((name, filepath, linum, 0))

                purified_content = ""

                repeat_times = 3
                for i, (name, filepath, linum, _) in enumerate(stacktrace):
                    desc = f"- {name} ({filepath}:{linum})\n"
                    if cwe is CWE.Stack_overflow:
                        has_cyclic = False
                        for cycle_len in range(1, i // repeat_times):
                            always_repeat = True
                            for j in range(cycle_len):
                                for k in range(repeat_times):
                                    always_repeat = always_repeat and (stacktrace[i - j] == stacktrace[i - j - cycle_len * k])
                            if always_repeat:
                                has_cyclic = True
                                purified_content += "  ... more stack frames\n"
                                break

                        if has_cyclic:
                            break

                    purified_content += desc

                return JazzerReport(Sanitizer.JazzerSanitizer, content, cwe, stacktrace, purified_content)

        return JazzerReport(Sanitizer.JazzerSanitizer, content, CWE.UNKNOWN, [])

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
