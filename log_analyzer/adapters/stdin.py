from __future__ import annotations

import sys
from collections.abc import AsyncIterator

from ..models import Event
from ..parsers.detector import FormatDetector
from ..parsers.registry import get_parser
from .base import SourceAdapter


class StdinAdapter(SourceAdapter):
    """Reads log events from stdin."""

    async def events(self) -> AsyncIterator[Event]:
        sample_lines: list[str] = []
        all_lines: list[str] = []

        for line in sys.stdin:
            all_lines.append(line)
            if len(sample_lines) < 5 and line.strip():
                sample_lines.append(line)

        fmt = FormatDetector().detect(sample_lines)
        parser = get_parser(fmt, source="stdin")

        for line in all_lines:
            event = parser.parse(line)
            if event is not None:
                yield event
