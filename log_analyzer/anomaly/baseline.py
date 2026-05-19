"""Baseline statistics for anomaly detection.

Stores per-feature mean and standard deviation computed from historical
(training) buckets.  Supports two scoring modes:

  * Z-score (always available, pure Python)
  * Isolation Forest (optional, requires scikit-learn)
"""
from __future__ import annotations

import math
from dataclasses import dataclass

_MIN_BUCKETS = 5  # minimum observations before baseline is considered trained


@dataclass
class FeatureStat:
    mean: float
    std: float
    n: int

    def zscore(self, value: float) -> float:
        """Signed z-score; returns 0 when std is negligible."""
        if self.std < 1e-10:
            return 0.0
        return (value - self.mean) / self.std


@dataclass
class BaselineStats:
    source_key: str
    n_buckets: int
    features: dict[str, FeatureStat]

    def is_trained(self) -> bool:
        return self.n_buckets >= _MIN_BUCKETS and bool(self.features)

    def zscore_dict(self, feature_dict: dict[str, float]) -> dict[str, float]:
        """Return a z-score for each feature that exists in both dicts."""
        return {
            name: stat.zscore(feature_dict[name])
            for name, stat in self.features.items()
            if name in feature_dict
        }


def compute_stats(
    feature_dicts: list[dict[str, float]],
    source_key: str,
) -> BaselineStats:
    """Compute mean and std for each feature across all stored observations.

    Args:
        feature_dicts: list of feature dicts (one per TimeBucket), loaded from DB.
        source_key: identifier for the log source.
    """
    if not feature_dicts:
        return BaselineStats(source_key=source_key, n_buckets=0, features={})

    # Aggregate per feature
    values: dict[str, list[float]] = {}
    for fd in feature_dicts:
        for name, val in fd.items():
            values.setdefault(name, []).append(float(val))

    features: dict[str, FeatureStat] = {}
    for name, vals in values.items():
        n = len(vals)
        mean = sum(vals) / n
        variance = sum((v - mean) ** 2 for v in vals) / max(n - 1, 1)
        features[name] = FeatureStat(mean=mean, std=math.sqrt(variance), n=n)

    return BaselineStats(
        source_key=source_key,
        n_buckets=len(feature_dicts),
        features=features,
    )
