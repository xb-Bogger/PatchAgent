import unittest
from pathlib import Path

from patchagent.logger import log
from patchagent.parser import Sanitizer, parse_sanitizer_report
from patchagent.parser.cwe import CWE


class TestSanitizer(unittest.TestCase):
    def test_parse_sanitizer_report(self):
        cover_error_type = set()
        for name in ["address", "reports", "skyset"]:
            sanitizer_report_dir = Path(__file__).parent / name
            for report_txt in sanitizer_report_dir.glob("**/report.txt"):
                case_dir = report_txt.parent
                raw_report = report_txt.read_text(encoding="utf-8", errors="ignore")
                summary_txt = case_dir / "summary.txt"

                if "ERROR: AddressSanitizer" in raw_report:
                    report = parse_sanitizer_report(raw_report, Sanitizer.AddressSanitizer)
                    assert report is not None
                    assert report.cwe is not CWE.UNKNOWN
                    cover_error_type.add(report.cwe)
                    assert report.summary == summary_txt.read_text()
                    summary_txt.write_text(report.summary)

                if "UndefinedBehaviorSanitizer" in raw_report:
                    report = parse_sanitizer_report(raw_report, Sanitizer.UndefinedBehaviorSanitizer)
                    assert report is not None
                    assert report.cwe is not CWE.UNKNOWN
                    cover_error_type.add(report.cwe)
                    assert report.summary == summary_txt.read_text()
                    summary_txt.write_text(report.summary)

                if "Java Exception" in raw_report:
                    report = parse_sanitizer_report(raw_report, Sanitizer.JazzerSanitizer)
                    assert report is not None
                    assert report.cwe is not CWE.UNKNOWN
                    cover_error_type.add(report.cwe)
                    assert report.summary == summary_txt.read_text()
                    summary_txt.write_text(report.summary)

        for error_type in CWE:
            if error_type not in cover_error_type and error_type is not CWE.UNKNOWN:
                log.warning(f"Missing test case for {error_type}")


if __name__ == "__main__":
    unittest.main()

# python -m patchagent.tests.test_parser
