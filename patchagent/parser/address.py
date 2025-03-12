import re
from pathlib import Path
from typing import List, Optional, Tuple

from patchagent.logger import log
from patchagent.parser.cwe import CWE, CWE_DESCRIPTIONS, CWE_REPAIR_ADVICE
from patchagent.parser.sanitizer import Sanitizer, SanitizerReport
from patchagent.parser.utils import guess_relpath

AddressSanitizerPattern = r"(==[0-9]+==ERROR: AddressSanitizer: .*)"
StackTracePattern = r"^\s*#(\d+)\s+(0x[\w\d]+)\s+in\s+(.+)\s+(/.*)\s*"
ANSIEscape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

cwe_pattern_map = {
    CWE.ILL: r"==[0-9]+==ERROR: AddressSanitizer: (ILL|illegal-instruction) on unknown address (0x[0-9a-f]+)*",
    CWE.ABORT: r"==[0-9]+==ERROR: AddressSanitizer: ABRT on unknown address (0x[0-9a-f]+)*",
    CWE.FPE: r"==[0-9]+==ERROR: AddressSanitizer: FPE on unknown address (0x[0-9a-f]+)*",
    CWE.Null_dereference: r"==[0-9]+==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000[0-9a-f]+",
    CWE.Segv_on_unknown_address: r"==[0-9]+==ERROR: AddressSanitizer: SEGV on unknown address (0x[0-9a-f]+)*",
    CWE.Heap_buffer_overflow: r"==[0-9]+==ERROR: AddressSanitizer: heap-buffer-overflow on address (0x[0-9a-f]+)*",
    CWE.Stack_buffer_overflow: r"==[0-9]+==ERROR: AddressSanitizer: stack-buffer-overflow on address (0x[0-9a-f]+)*",
    CWE.Stack_buffer_underflow: r"==[0-9]+==ERROR: AddressSanitizer: stack-buffer-underflow on address (0x[0-9a-f]+)*",
    CWE.Dynamic_stack_buffer_overflow: r"==[0-9]+==ERROR: AddressSanitizer: dynamic-stack-buffer-overflow on address (0x[0-9a-f]+)*",
    CWE.Global_buffer_overflow: r"==[0-9]+==ERROR: AddressSanitizer: global-buffer-overflow on address (0x[0-9a-f]+)*",
    CWE.Container_overflow: r"==[0-9]+==ERROR: AddressSanitizer: container-overflow on address (0x[0-9a-f]+)*",
    CWE.Negative_size_param: r"==[0-9]+==ERROR: AddressSanitizer: negative-size-param: \(size=[-0-9]+\)*",
    CWE.Memcpy_param_overlap: r"==[0-9]+==ERROR: AddressSanitizer: memcpy-param-overlap: .+",
    # NOTE: Index_out_of_bounds have no test case
    CWE.Index_out_of_bounds: r"==[0-9]+==ERROR: AddressSanitizer: index-out-of-bounds on address (0x[0-9a-f]+)*",
    CWE.Stack_overflow: r"==[0-9]+==ERROR: AddressSanitizer: stack-overflow on address (0x[0-9a-f]+)*",
    CWE.Stack_use_after_return: r"==[0-9]+==ERROR: AddressSanitizer: stack-use-after-return on address (0x[0-9a-f]+)*",
    # NOTE: Stack_use_after_scope have no test case
    CWE.Stack_use_after_scope: r"==[0-9]+==ERROR: AddressSanitizer: stack-use-after-scope on address (0x[0-9a-f]+)*",
    CWE.Heap_double_free: r"==[0-9]+==ERROR: AddressSanitizer: attempting double-free on (0x[0-9a-f]+)*",
    CWE.Heap_use_after_free: r"==[0-9]+==ERROR: AddressSanitizer: heap-use-after-free on address (0x[0-9a-f]+)*",
    CWE.Invalid_free: r"==[0-9]+==ERROR: AddressSanitizer: attempting free on address which was not malloc\(\)-ed: (0x[0-9a-f]+)*",
    # NOTE: Bad_free have no test case
    CWE.Bad_free: r"==[0-9]+==ERROR: AddressSanitizer: (bad-free|wild-free) on address (0x[0-9a-f]+)*",
    # NOTE: Bad_cast have no test case
    CWE.Bad_cast: r"==[0-9]+==ERROR: AddressSanitizer: bad-cast on address (0x[0-9a-f]+)*",
}


class AddressSanitizerReport(SanitizerReport):
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
    def parse(raw_content: str, source_path: Optional[Path] = None, work_path: Optional[Path] = None) -> Optional["AddressSanitizerReport"]:
        raw_content = ANSIEscape.sub("", raw_content)
        match = re.search(AddressSanitizerPattern, raw_content, re.DOTALL)
        if match is None:
            return None

        content = match.group(1)
        lines = content.splitlines()
        header, body = lines[0], lines[1:]

        def is_interesting(line: str) -> bool:
            if line.startswith("SCARINESS") or line.startswith("DEDUP_TOKEN"):
                return False
            if line.strip() == "AddressSanitizer can not provide additional info.":
                return False
            return True

        body = filter(is_interesting, body)
        for cwe, pattern in cwe_pattern_map.items():
            match = re.search(pattern, header)
            if match is not None:
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

                            # NOTE: Here is an example of the entries list length may be greater than 3
                            # - /usr/src/zlib-1:1.3.dfsg-3.1ubuntu2/inflate.c:429:9
                            # - /usr/src/zlib-1:1.3.dfsg-3.1ubuntu2/inflate.c:1279:13
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

                            # NOTE:
                            # We handle stacktraces and description messages differently based on the presence of a work_path.
                            #
                            # Stacktraces:
                            # - When a work_path is provided and the normalized source path is within that work_path,
                            #   we store only the relative path (relative to work_path) along with the function name,
                            #   line number, and column number.
                            # - If the source path is not directly relative to work_path, we attempt to compute a relative path
                            #   using the guess_relpath() function. If successful, we store that instead.
                            #
                            # Descriptions:
                            # - If work_path is not provided, the full description (desc) is used.
                            # - When work_path is provided and the source path is within work_path,
                            #   we output the relative path with appended line and column numbers.

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

                asan_report = AddressSanitizerReport(content, cwe, stacktraces[0], "\n".join(body), stacktraces[1:])
                return asan_report

        log.warning(f"Unknown AddressSanitizer report: {content}")
        return AddressSanitizerReport(content, CWE.UNKNOWN, [], content)

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
