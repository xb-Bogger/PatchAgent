import os
import re
from pathlib import Path

from patchagent.logger import log


def revise_patch(patch: str, project_path: Path) -> tuple[str, bool]:
    def revise_hunk(lines: list[str], file_content: list[str]) -> tuple[str, bool]:
        orignal_line_number = sum(1 for line in lines[1:] if not line.startswith("+"))
        patched_line_number = sum(1 for line in lines[1:] if not line.startswith("-"))

        # @@ -3357,10 +3357,16 @@
        # extract the line number and the number of lines
        numbers = re.findall(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@", lines[0])[0]
        if numbers[0] != numbers[2]:
            fixed = True

        hunk = ""
        modified_line_number = None
        corrected_line_number = None

        for test_line_no in range(max(1, int(numbers[0]) - 5), min(len(file_content) - len(lines), int(numbers[0]) + 5)):
            temp_hunk = ""
            temp_modified_line_number = 0
            line_number = test_line_no

            for line_no in range(1, len(lines)):
                if lines[line_no].startswith("-"):
                    if lines[line_no][1:].strip() != file_content[line_number - 1].strip():
                        temp_modified_line_number += 1
                    temp_hunk += "-" + file_content[line_number - 1]
                    line_number += 1
                elif lines[line_no].startswith("+"):
                    temp_hunk += lines[line_no] + "\n"
                else:
                    if lines[line_no].strip() != file_content[line_number - 1].strip():
                        temp_modified_line_number += 1
                    temp_hunk += " " + file_content[line_number - 1]
                    line_number += 1

            if modified_line_number is None or temp_modified_line_number < modified_line_number:
                modified_line_number = temp_modified_line_number
                corrected_line_number = test_line_no
                hunk = temp_hunk

        header = f"@@ -{corrected_line_number},{orignal_line_number} +{corrected_line_number},{patched_line_number} @@\n"
        fixed = (
            modified_line_number != 0
            or corrected_line_number != int(numbers[0])
            or orignal_line_number != int(numbers[1])
            or corrected_line_number != int(numbers[2])
            or patched_line_number != int(numbers[3])
        )

        return header + hunk, fixed

    def revise_block(lines: list[str]) -> tuple[list[str], bool]:
        file_path_a = re.findall(r"--- a/(.*)", lines[0])[0]
        file_path_b = re.findall(r"\+\+\+ b/(.*)", lines[1])[0]
        fixed_file_path_a = os.path.normpath(file_path_a)
        fixed_file_path_b = os.path.normpath(file_path_b)
        block_fixed = file_path_a != fixed_file_path_a or file_path_b != fixed_file_path_b

        assert file_path_a == file_path_b and fixed_file_path_a == fixed_file_path_b
        fixed_lines = [
            f"--- a/{fixed_file_path_a}\n",
            f"+++ b/{fixed_file_path_b}\n",
        ]

        with open(os.path.join(project_path, file_path_a), "r") as f:
            file_content = f.readlines()

        last_line = -1
        for line_no in range(2, len(lines)):
            if lines[line_no].startswith("@@"):
                if last_line != -1:
                    hunk_lines, hunk_fixed = revise_hunk(lines[last_line:line_no], file_content)
                    fixed_lines.append(hunk_lines)
                    block_fixed = block_fixed or hunk_fixed
                last_line = line_no
        if last_line != -1:
            hunk_lines, hunk_fixed = revise_hunk(lines[last_line:], file_content)
            fixed_lines.append(hunk_lines)
            block_fixed = block_fixed or hunk_fixed

        return fixed_lines, block_fixed

    try:
        lines = patch.splitlines()
        fixed_lines = []

        last_line = -1
        fixed = False
        for line_no in range(len(lines)):
            if lines[line_no].startswith("--- a/"):
                if last_line != -1:
                    block_lines, block_fixed = revise_block(lines[last_line:line_no])
                    fixed_lines += block_lines
                    fixed = fixed or block_fixed
                last_line = line_no
        if last_line != -1:
            block_lines, block_fixed = revise_block(lines[last_line:])
            fixed_lines += block_lines
            fixed = fixed or block_fixed

        return "".join(fixed_lines), fixed
    except Exception:
        log.warning("Failed to revise patch")
        return patch, False
