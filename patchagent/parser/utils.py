from pathlib import Path
from typing import Optional

from patchagent.logger import log

_pathset_cache: dict[Path, set[Path]] = {}


def guess_relpath(source_path: Optional[Path], original_path: Path) -> Optional[Path]:
    if source_path is None:
        return None

    if source_path not in _pathset_cache:
        _pathset_cache[source_path] = set(p.relative_to(source_path) for p in source_path.rglob("*") if p.is_file())

    def common_suffix_length(a: Path, b: Path) -> int:
        count = 0
        for part_a, part_b in zip(reversed(a.parts), reversed(b.parts)):
            if part_a != part_b:
                break
            count += 1
        return count

    relpath = None
    max_length = 0
    for p in _pathset_cache[source_path]:
        length = common_suffix_length(p, original_path)
        if length > max_length:
            max_length = length
            relpath = p

    log.info(f"[🔍] Guessed relpath {original_path} -> {relpath}")
    return relpath
