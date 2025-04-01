import subprocess
from functools import cached_property
from pathlib import Path
from typing import Dict, List

from patchagent.logger import logger
from patchagent.lsp.language import LanguageServer
from patchagent.utils import subprocess_none_pipe


class CtagsServer(LanguageServer):
    def __init__(self, source_path: Path):
        super().__init__(source_path)

    @cached_property
    def symbol_map(self) -> Dict:
        tagfile = self.source_path / "tags"

        subprocess.check_call(
            ["ctags", "--excmd=number", "--exclude=Makefile", "-f", tagfile, "-R"],
            cwd=self.source_path,
            stdin=subprocess.DEVNULL,
            stdout=subprocess_none_pipe(),
            stderr=subprocess_none_pipe(),
        )

        assert tagfile.is_file(), "Failed to generate ctags"

        symbol_map: Dict[str, List[str]] = {}
        with open(tagfile, "rb") as f:
            for line in f.readlines():
                try:
                    if text := line.decode("utf-8", errors="ignore"):
                        if text.startswith("!_TAG_"):
                            continue
                        symbol, path, line_info = text.split(';"')[0].split("\t")
                        if symbol not in symbol_map:
                            symbol_map[symbol] = []
                        symbol_map[symbol].append(f"{path}:{line_info}")
                except ValueError:
                    logger.warning(f"Failed to decode line {line!r} in ctags file")

        return symbol_map

    def locate_symbol(self, symbol: str) -> List[str]:
        return self.symbol_map.get(symbol, [])
