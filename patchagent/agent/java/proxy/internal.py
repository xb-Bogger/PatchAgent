import math
import os
from pathlib import Path
from typing import Dict, Tuple

from patchagent.agent.base import AgentStopException, PatchFoundException
from patchagent.agent.java.proxy.utils import revise_patch
from patchagent.logger import logger
from patchagent.task import PatchTask, ValidationResult

MAX_VIEWCODE_LINES = 40
MAX_VALIDATION_TRIES = 3


def viewcode(task: PatchTask, _path: str, _start_line: int, _end_line: int, auto_hint=False) -> Tuple[Dict, str]:
    total_lines = _end_line - _start_line + 1
    adjusted_lines = max(MAX_VIEWCODE_LINES, total_lines) - total_lines

    path = Path(os.path.normpath(_path).lstrip("/"))
    start_line = max(1, _start_line - math.floor(adjusted_lines / 2))
    end_line = _end_line + math.ceil(adjusted_lines / 2)

    lines = task.builder.language_server.viewcode(path, start_line, end_line)

    if lines is None:
        result = f"Sorry, the file {path} does not exist."
    else:
        end_line = min(end_line, start_line + len(lines) - 1)
        desc = f"Here is the code snippet from line {start_line} to line {end_line} in {path}:\n"

        code = "".join(f"{start_line + i:{math.floor(math.log10(end_line)) + 1}}| {line}" for i, line in enumerate(lines))
        result = desc + code

    return {"path": path.as_posix(), "start_line": start_line, "end_line": end_line}, result


def locate(task: PatchTask, symbol: str, auto_hint=False) -> Tuple[Dict, str]:
    locations = task.builder.language_server.locate_symbol(symbol)

    if len(locations) > 1:
        logger.warning(f"{symbol} has multiple definitions.")
    elif len(locations) == 0:
        logger.error(f"Failed to find the definition of {symbol}.")

    if len(locations) == 0:
        result = f"Sorry, we cannot locate the symbol {symbol}, please consider use some alias names."
    else:
        result = f"Here is the location of the symbol {symbol}:\n" + "\n".join(locations)

    return {"symbol": symbol}, result


def validate(task: PatchTask, patch: str, auto_hint=False) -> Tuple[Dict, str]:
    num_tries = 0
    for tool_call in reversed(task.current_context.tool_calls):
        if tool_call["name"] != "validate":
            break
        num_tries += 1

    if num_tries >= MAX_VALIDATION_TRIES:
        raise AgentStopException("The number of validation tries has reached the maximum limit.")

    revised_patch = revise_patch(patch)
    ret, real_patch, report = task.validate(revised_patch)

    if ret == ValidationResult.Success:
        task.current_context.patch = real_patch
        raise PatchFoundException(real_patch)

    if ret == ValidationResult.InvalidPatchFormat:
        report = (
            "Invalid patch format, you may view the code to get the context.\n"
            "1. At the beginning and end of the hunk, there must be at least 1 lines of context.\n"
            "2. DO not use newline and comment as the start or the end of the context.\n"
            "3. Do not add comments in the patch.\n"
            "4. ALL changes must start with +, -.\n"
            "5. If you use a new package, you must import it.\n"
        )

    header = "Sorry, the patch is incorrect. Here is the applied patch, which may have been revised and differ from the original:"
    desc = f"Here is the validation report:\n{report}"

    result = f"{header}\n Here is your generated {patch} \n{desc}"
    return {"patch": real_patch}, result
