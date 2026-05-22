from __future__ import annotations

import gzip
from collections.abc import AsyncIterator
from pathlib import Path

from ..models import Event
from ..parsers.detector import FormatDetector
from ..parsers.registry import get_parser
from .base import SourceAdapter


class FileAdapter(SourceAdapter):
    """Reads log events from a single file (plain or gzip-compressed)."""

    def __init__(self, path: Path) -> None:
        self.path = path

    async def events(self) -> AsyncIterator[Event]:
        lines = self._read_lines()
        sample = []
        buf = []
        for line in lines:
            buf.append(line)
            if len(sample) < 5 and line.strip():
                sample.append(line)
            if len(buf) >= 512:
                break

        fmt = FormatDetector().detect(sample)
        parser = get_parser(fmt, source=str(self.path))

        for line in buf:
            event = parser.parse(line)
            if event is not None:
                yield event

        for line in self._read_lines(skip=len(buf)):
            event = parser.parse(line)
            if event is not None:
                yield event

    def _read_lines(self, skip: int = 0):
        open_fn = gzip.open if self.path.suffix == ".gz" else open
        with open_fn(self.path, "rt", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i < skip:
                    continue
                yield line
