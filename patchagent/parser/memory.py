import re
from pathlib import Path
from typing import List, Optional, Tuple

from patchagent.logger import log
from patchagent.parser.cwe import CWE, CWE_DESCRIPTIONS, CWE_REPAIR_ADVICE
from patchagent.parser.sanitizer import Sanitizer, SanitizerReport
from patchagent.parser.utils import guess_relpath

MemorySanitizerPattern = r"(MemorySanitizer: .*SUMMARY: MemorySanitizer: [^\n]+)"

StackTracePattern = r"^\s*#(\d+)\s+(0x[\w\d]+)\s+in\s+(.+)\s+(/.*)\s*"
ANSIEscape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

cwe_pattern_map = {
    CWE.Use_of_uninitialized_memory: r"MemorySanitizer: use-of-uninitialized-value.*",
    CWE.Null_dereference: r"MemorySanitizer: SEGV on unknown address 0x000000000[0-9a-f]+",
    CWE.Segv_on_unknown_address: r"MemorySanitizer: SEGV on unknown address (0x[0-9a-f]+)*",
}


class MemorySanitizerReport(SanitizerReport):
    def __init__(
        self,
        content: str,
        cwe: CWE,
        stacktrace: List[Tuple[str, Path, int, int]],
        purified_content: str,
        other_stacktraces: List[List[Tuple[str, Path, int, int]]] = [],
    ):

        super().__init__(Sanitizer.AddressSanitizer, content, cwe, stacktrace)
        self.purified_content = purified_content
        self.other_stacktraces = other_stacktraces

    @property
    def stacktraces(self) -> List[List[Tuple[str, Path, int, int]]]:
        return [self.stacktrace] + self.other_stacktraces

    @staticmethod
    def parse(raw_content: str, source_path: Optional[Path] = None, work_path: Optional[Path] = None) -> Optional["MemorySanitizerReport"]:
        raw_content = ANSIEscape.sub("", raw_content)
        match = re.search(MemorySanitizerPattern, raw_content, re.DOTALL)
        if match is None:
            return None

        content = match.group(1)
        lines = content.splitlines()
        header, body = lines[0], lines[1:]

        def is_interesting(line: str) -> bool:
            if line.startswith("SCARINESS") or line.startswith("DEDUP_TOKEN") or line.startswith("SUMMARY"):
                return False
            if line.startswith("MemorySanitizer can not provide additional info."):
                return False
            return True

        body = filter(is_interesting, body)

        for cwe, pattern in cwe_pattern_map.items():
            if not re.match(pattern, header):
                continue

            old_body, body = body, []
            stacktraces: List[List[Tuple[str, Path, int, int]]] = [[]]
            current_count = -1
            for line in old_body:
                if line.strip().startswith("SUMMARY:"):
                    break

                if line.strip().startswith("#"):
                    count = int(line.split()[0][1:])
                    if count == current_count + 1:
                        current_count += 1
                    else:
                        stacktraces.append([])
                        current_count = 0
                        assert count == 0

                    if (match := re.search(StackTracePattern, line)) is not None:
                        function_name = match.group(3)
                        entries = match.group(4).split(":")

                        while len(entries) > 3 or (len(entries) > 1 and any(not c.isdigit() for c in entries[1:])):
                            entries[0] = entries[0] + ":" + entries[1]
                            entries.pop(1)

                        if len(entries) == 0:
                            continue

                        while len(entries) < 3:
                            entries.append("0")
                        filepath, line_number, column_number = entries
                        assert filepath.startswith("/")

                        normpath = Path(filepath).resolve()
                        desc = f"{normpath}:{line_number}:{column_number}"
                        if f"{filepath}:{line_number}:{column_number}" != match.group(4):
                            log.warning(f"Incomplete file path: {desc} vs {match.group(4)}")

                        if work_path is not None and normpath.is_relative_to(work_path):
                            stacktraces[-1].append((function_name, normpath.relative_to(work_path), int(line_number), int(column_number)))
                        elif (relpath := guess_relpath(source_path, normpath)) is not None:
                            stacktraces[-1].append((function_name, relpath, int(line_number), int(column_number)))

                        if work_path is None:
                            body.append(f"    - {function_name} {desc}")
                        elif normpath.is_relative_to(work_path):
                            body.append(f"    - {function_name} {normpath.relative_to(work_path)}:{line_number}:{column_number}")
                else:
                    body.append(re.sub(r"==[0-9]+==", "", line))

            return MemorySanitizerReport(content, cwe, stacktraces[0], "\n".join(body), stacktraces[1:])

        return MemorySanitizerReport(content, CWE.UNKNOWN, [], "")

    @property
    def summary(self) -> str:
        if self.cwe == CWE.UNKNOWN:
            return self.content

        summary = (
            f"The sanitizer detected a {self.cwe.value} vulnerability. "
            f"The explanation of the vulnerability is: {CWE_DESCRIPTIONS[self.cwe]}. "
            f"Here is the detail: \n\n{self.purified_content}\n\n"
            f"To fix this issue, follow the advice below:\n\n{CWE_REPAIR_ADVICE[self.cwe]}"
        )

        return summary
