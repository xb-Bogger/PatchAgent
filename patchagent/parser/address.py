import re
from pathlib import Path
from typing import List, Optional, Tuple

from patchagent.logger import log
from patchagent.parser.cwe import CWE, CWE_DESCRIPTIONS, CWE_REPAIR_ADVICE
from patchagent.parser.sanitizer import Sanitizer, SanitizerReport
from patchagent.parser.utils import simplify_and_extract_stacktraces

AddressSanitizerPattern = r"(==[0-9]+==ERROR: AddressSanitizer: .*)"
LeakAddressSanitizerPattern = r"(==[0-9]+==ERROR: LeakSanitizer: detected memory leaks.*)"
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

LeakAddressSanitizerPattern = r"(==[0-9]+==ERROR: LeakSanitizer: detected memory leaks.*)"


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
    def parse(raw_content: str, source_path: Optional[Path] = None, work_path: Optional[Path] = None, detect_leak: bool = False) -> Optional["AddressSanitizerReport"]:
        raw_content = ANSIEscape.sub("", raw_content)
        match = re.search(AddressSanitizerPattern, raw_content, re.DOTALL) or (re.search(LeakAddressSanitizerPattern, raw_content, re.DOTALL) if detect_leak else None)
        if match is None:
            return None

        content = match.group(1)
        lines = content.splitlines()
        header = lines[0]

        body = []
        for line in lines[1:]:
            if line.startswith("SCARINESS") or line.startswith("DEDUP_TOKEN"):
                continue
            if line.strip() == "AddressSanitizer can not provide additional info.":
                continue
            if line.startswith("SUMMARY:"):
                break
            body.append(line)

        search_patterns = cwe_pattern_map.copy()
        if detect_leak:
            search_patterns[CWE.Memory_Leak] = LeakAddressSanitizerPattern

        for cwe, pattern in search_patterns.items():
            if re.search(pattern, header) is not None:
                simplified, stacktraces = simplify_and_extract_stacktraces(body, source_path, work_path)
                asan_report = AddressSanitizerReport(content, cwe, stacktraces[0], simplified, stacktraces[1:])
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
