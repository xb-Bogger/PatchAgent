from pathlib import Path
from typing import Optional, Union

from patchagent.parser.address import AddressSanitizerReport
from patchagent.parser.cwe import CWE
from patchagent.parser.sanitizer import Sanitizer, SanitizerReport


class LeakAddressSanitizerReport(SanitizerReport):
    def __init__(self, content: str):
        super().__init__(Sanitizer.LeakAddressSanitizer, content, CWE.Memory_Leak, [])

    @staticmethod
    def parse(
        content: str, source_path: Optional[Path] = None, work_path: Optional[Path] = None, *args, **kwargs
    ) -> Union[None, "AddressSanitizerReport", "LeakAddressSanitizerReport"]:
        leak_str = "ERROR: LeakSanitizer: detected memory leaks"

        if leak_str not in content:
            return AddressSanitizerReport.parse(content, source_path=source_path, work_path=work_path)
        else:
            return LeakAddressSanitizerReport(content)

    @property
    def summary(self) -> str:
        return "Memory leak detected, please carefully check the codebase and make sure to free the memory properly."
