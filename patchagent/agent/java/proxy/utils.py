import re
from typing import List


def revise_patch(patch: str) -> str:
    def revise_hunk_header(lines: List[str]) -> List[str]:
        # Important! remove the newline after the header
        for i in range(len(lines)):
            if not lines[1].strip():
                lines.pop(1)
            else:
                break
        orignal_line_number = sum(1 for line in lines[1:] if not line.startswith("+"))
        patched_line_number = sum(1 for line in lines[1:] if not line.startswith("-"))
        line_numbers = re.findall(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@", lines[0])[0]
        header = f"@@ -{line_numbers[0]},{orignal_line_number} +{line_numbers[2]},{patched_line_number} @@"
        return [header] + lines[1:]

    def revise_block_header(lines: List[str]) -> List[str]:

        # find the hunk header
        hunk_start_index = []
        for index, line in enumerate(lines):
            if line.startswith("@@"):
                hunk_start_index.append(index)
        block_lines = []
        # multiple blocks
        for i in range(len(hunk_start_index) - 1):
            block_lines += revise_hunk_header(lines[hunk_start_index[i] : hunk_start_index[i + 1]])
        block_lines += revise_hunk_header(lines[hunk_start_index[-1] :])
        return block_lines

    # first find the block starts with --- and +++
    all_lines = patch.splitlines()
    block_start_index = []
    for index, line in enumerate(all_lines):
        if line.startswith("---"):
            block_start_index.append(index)

    # reconstruct the patch
    revised_patch = []
    for i in range(len(block_start_index) - 1):
        file_header = all_lines[block_start_index[i] : block_start_index[i] + 2]
        revised_block = file_header + revise_block_header(all_lines[block_start_index[i] + 2 : block_start_index[i + 1]])
        revised_patch += revised_block

    file_header = all_lines[block_start_index[-1] : block_start_index[-1] + 2]
    revised_block = file_header + revise_block_header(all_lines[block_start_index[-1] + 2 :])
    revised_patch += revised_block

    revised_patch = "\n".join(revised_patch)
    return revised_patch.strip()
