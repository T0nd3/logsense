"""Feature extraction: bucket events into time windows and compute numeric features.

Each TimeBucket covers one time window (default: 60 seconds) and exposes
a flat dict of numeric features suitable for z-score or Isolation Forest scoring.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import UTC, datetime

from ..models import Event, Severity

_ERROR_SEVERITIES = {Severity.ERROR, Severity.CRITICAL}


class TimeBucket:
    """Aggregated numeric features for one time window."""

    def __init__(self, ts: datetime, bucket_seconds: int = 60) -> None:
        self.ts = ts
        self.bucket_seconds = bucket_seconds
        # Counters
        self.event_count: int = 0
        self.error_count: int = 0
        self.warning_count: int = 0
        self.http_5xx_count: int = 0
        self.http_4xx_count: int = 0
        self.total_bytes: int = 0
        self.bytes_count: int = 0
        # Sets / lists (not exported directly)
        self._sources: set[str] = set()
        self._path_tokens: list[str] = []

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def error_rate(self) -> float:
        return self.error_count / self.event_count if self.event_count else 0.0

    @property
    def warning_rate(self) -> float:
        return self.warning_count / self.event_count if self.event_count else 0.0

    @property
    def source_count(self) -> float:
        return float(len(self._sources))

    @property
    def avg_bytes(self) -> float:
        return self.total_bytes / self.bytes_count if self.bytes_count else 0.0

    @property
    def path_entropy(self) -> float:
        """Shannon entropy (bits) of the path/token distribution."""
        if not self._path_tokens:
            return 0.0
        counts: dict[str, int] = defaultdict(int)
        for tok in self._path_tokens:
            counts[tok] += 1
        total = len(self._path_tokens)
        return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)

    def to_feature_dict(self) -> dict[str, float]:
        return {
            "event_count": float(self.event_count),
            "error_rate": self.error_rate,
            "warning_rate": self.warning_rate,
            "source_count": self.source_count,
            "http_5xx_count": float(self.http_5xx_count),
            "http_4xx_count": float(self.http_4xx_count),
            "avg_bytes": self.avg_bytes,
            "path_entropy": self.path_entropy,
        }

    def __repr__(self) -> str:
        return (
            f"TimeBucket(ts={self.ts.isoformat()}, events={self.event_count}, "
            f"err_rate={self.error_rate:.2f})"
        )


class FeatureExtractor:
    """Group events into fixed-width time buckets and extract features."""

    def __init__(self, bucket_seconds: int = 60) -> None:
        self._bucket_seconds = bucket_seconds

    def extract(self, events: list[Event]) -> list[TimeBucket]:
        if not events:
            return []

        buckets: dict[datetime, TimeBucket] = {}

        for event in events:
            if not event.timestamp:
                continue

            # Snap to bucket boundary (UTC)
            raw_ts = event.timestamp.timestamp()
            bucket_epoch = (raw_ts // self._bucket_seconds) * self._bucket_seconds
            bucket_ts = datetime.fromtimestamp(bucket_epoch, tz=UTC)

            if bucket_ts not in buckets:
                buckets[bucket_ts] = TimeBucket(bucket_ts, self._bucket_seconds)

            b = buckets[bucket_ts]
            b.event_count += 1
            b._sources.add(event.source)

            if event.severity in _ERROR_SEVERITIES:
                b.error_count += 1
            elif event.severity == Severity.WARNING:
                b.warning_count += 1

            # HTTP status
            status = event.parsed_fields.get("status")
            if status is not None:
                try:
                    s = int(status)
                    if s >= 500:
                        b.http_5xx_count += 1
                    elif s >= 400:
                        b.http_4xx_count += 1
                except (ValueError, TypeError):
                    pass

            # Bytes transferred
            for key in ("bytes", "body_bytes_sent", "bytes_sent", "size"):
                val = event.parsed_fields.get(key)
                if val is not None:
                    try:
                        b.total_bytes += int(val)
                        b.bytes_count += 1
                        break
                    except (ValueError, TypeError):
                        pass

            # Path tokens for entropy
            path = (
                event.parsed_fields.get("path")
                or event.parsed_fields.get("request")
                or event.parsed_fields.get("url")
            )
            if path:
                # First path segment as token
                seg = str(path).lstrip("/").split("/")[0] or str(path)[:30]
                b._path_tokens.append(seg)
            elif event.message:
                # Coarse proxy: first word of message
                b._path_tokens.append(event.message.split()[0][:30])

        return sorted(buckets.values(), key=lambda b: b.ts)
