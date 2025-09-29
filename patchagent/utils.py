import os
import subprocess
from pathlib import Path
from typing import Optional

'''通用工具函数'''
def debug_mode() -> bool:
    return os.getenv("PATCH_DEBUG", "0") == "1"


def subprocess_none_pipe() -> Optional[int]:
    return None if debug_mode() else subprocess.DEVNULL


def bear_path() -> Path:
    return Path(__file__).parent / ".bear"
