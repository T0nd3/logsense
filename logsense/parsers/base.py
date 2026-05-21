from abc import ABC, abstractmethod

from ..models import Event


class BaseParser(ABC):
    def __init__(self, source: str) -> None:
        self.source = source

    @abstractmethod
    def parse(self, line: str) -> Event | None:
        """Parse a single log line. Returns None for empty/unparseable lines."""
        ...
