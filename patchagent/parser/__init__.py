from typing import Optional

from patchagent.parser.address import AddressSanitizerReport
from patchagent.parser.jazzer import JazzerReport
from patchagent.parser.leak import LeakAddressSanitizerReport
from patchagent.parser.sanitizer import Sanitizer, SanitizerReport
from patchagent.parser.undefined import UndefinedBehaviorSanitizerReport


def parse_sanitizer_report(content: str, sanitizer: Sanitizer, *args, **kwargs) -> Optional[SanitizerReport]:
    __sanitizer_report_classes_map__ = {
        Sanitizer.AddressSanitizer: AddressSanitizerReport,
        Sanitizer.LeakAddressSanitizer: LeakAddressSanitizerReport,
        Sanitizer.UndefinedBehaviorSanitizer: UndefinedBehaviorSanitizerReport,
        Sanitizer.JazzerSanitizer: JazzerReport,
    }
    if sanitizer in __sanitizer_report_classes_map__:
        return __sanitizer_report_classes_map__[sanitizer].parse(content, *args, **kwargs)
