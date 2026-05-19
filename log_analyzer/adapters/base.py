from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from ..models import Event


class SourceAdapter(ABC):
    """Base class for all log source adapters.

    Implementors must yield normalized Event objects via async iteration.
    Phase 1 adapters use sync I/O internally; Phase 7 will replace internals
    with true async I/O — the interface stays identical.
    """

    @abstractmethod
    def events(self) -> AsyncIterator[Event]:
        ...
