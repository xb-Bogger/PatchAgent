import re
from pathlib import Path
from typing import List, Optional, Tuple

from patchagent.parser.cwe import CWE
from patchagent.parser.sanitizer import Sanitizer, SanitizerReport
from patchagent.parser.utils import guess_relpath

UndefinedBehaviorSanitizerPattern = r"(runtime error: .+?SUMMARY: [^\n]+)"
UndefinedBehaviorDescriptionPattern = r"runtime error: ([^\n]+)"
UndefinedBehaviorTriggerPointPattern = r"SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ([^\n]+) in"

StackTracePattern = r"^\s*#(\d+)\s+(0x[\w\d]+)\s+in\s+(.+)\s+(/.*)\s*"
ANSIEscape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


class UndefinedBehaviorSanitizerReport(SanitizerReport):
    def __init__(
        self,
        content: str,
        cwe: CWE,
        stacktrace: List[Tuple[str, Path, int, int]],
        purified_content: str,
    ):

        super().__init__(Sanitizer.AddressSanitizer, content, cwe, stacktrace)
        self.purified_content = purified_content

    @property
    def stacktraces(self) -> List[List[Tuple[str, Path, int, int]]]:
        return [self.stacktrace]

    @staticmethod
    def parse(raw_content: str, source_path: Optional[Path] = None, work_path: Optional[Path] = None) -> Optional["UndefinedBehaviorSanitizerReport"]:
        raw_content = ANSIEscape.sub("", raw_content)
        match = re.search(UndefinedBehaviorSanitizerPattern, raw_content, re.DOTALL)
        if match is None:
            return None

        content = match.group(0)
        desc_match = re.search(UndefinedBehaviorDescriptionPattern, content)
        if desc_match is None:
            return UndefinedBehaviorSanitizerReport(content, CWE.UNKNOWN, [], content)

        desc = desc_match.group(1)
        purified_content = f"The sanitizer detected an undefined behavior in the code.\nIts description is: {desc}.\n"

        body = content.splitlines()[1:-1]

        stacktrace: List[Tuple[str, Path, int, int]] = []
        raw_stacktrace: List[Tuple[str, Path, int, int]] = []

        current_count = -1
        for line in body:
            line = line.strip()
            if line.startswith("#"):
                count = int(line.split()[0][1:])
                if count != current_count + 1:
                    break

                current_count += 1
                if (match := re.search(StackTracePattern, line)) is not None:
                    # NOTE: The code is copied from address.py
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

                    raw_stacktrace.append((function_name, normpath, int(line_number), int(column_number)))
                    if work_path is not None and normpath.is_relative_to(work_path):
                        stacktrace.append((function_name, normpath.relative_to(work_path), int(line_number), int(column_number)))
                    elif (relpath := guess_relpath(source_path, normpath)) is not None:
                        stacktrace.append((function_name, relpath, int(line_number), int(column_number)))

        if len(raw_stacktrace) == 0:
            trigger_point_match = re.search(UndefinedBehaviorTriggerPointPattern, content)
            if trigger_point_match is not None:
                trigger_point = Path(trigger_point_match.group(1))

                if work_path is not None and trigger_point.is_relative_to(work_path):
                    trigger_point = trigger_point.relative_to(work_path)
                elif source_path is not None and (relpath := guess_relpath(source_path, trigger_point)) is not None:
                    trigger_point = relpath

                purified_content += f"The trigger point is located at {trigger_point}."
        else:
            stacktrace_desc = "\n".join(f"  - {fname} at {path}:{linum}:{column}" for fname, path, linum, column in raw_stacktrace)
            purified_content += f"The stacktrace is:\n{stacktrace_desc}"

        return UndefinedBehaviorSanitizerReport(content, CWE.UNKNOWN, stacktrace, purified_content)

    @property
    def summary(self) -> str:
        return self.purified_content
