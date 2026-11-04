"""Chronological dataset partitioning and anti-leakage guards (P8).

Enforces strict block boundary chronological splitting (70% train, 15% val, 15% test)
with explicit DataLeakageError guard and train-only fitted robust scaling.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import Any, Sequence

try:
    import numpy as np  # type: ignore
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


class DataLeakageError(ValueError):
    """Raised when chronological, target, or scaler data leakage is detected."""
    pass


@dataclass
class DatasetSplit:
    """Represents a dataset partition with features, labels, addresses, and block metadata."""
    features: Any  # list[list[float]] or np.ndarray
    labels: list[int]
    addresses: list[str]
    blocks: list[int]

    def __len__(self) -> int:
        return len(self.features)


def validate_no_data_leakage(
    train_split: DatasetSplit,
    val_split: DatasetSplit,
    test_split: DatasetSplit,
) -> bool:
    """Validates zero leakage across train, val, and test splits.

    Enforces invariants:
    1. max(train_blocks) < min(val_blocks)
    2. max(val_blocks) < min(test_blocks)
    3. No overlap in (block, address) identifier tuples across splits.
    """
    if len(train_split) > 0 and len(val_split) > 0:
        max_train = max(train_split.blocks)
        min_val = min(val_split.blocks)
        if max_train >= min_val:
            raise DataLeakageError(
                f"Temporal leakage detected: max(train_blocks)={max_train} >= min(val_blocks)={min_val}. "
                "Training data contains information from future validation blocks."
            )

    if len(val_split) > 0 and len(test_split) > 0:
        max_val = max(val_split.blocks)
        min_test = min(test_split.blocks)
        if max_val >= min_test:
            raise DataLeakageError(
                f"Temporal leakage detected: max(val_blocks)={max_val} >= min(test_blocks)={min_test}. "
                "Validation data contains information from future test blocks."
            )

    # Check identifier disjointness
    train_keys = set(zip(train_split.blocks, train_split.addresses))
    val_keys = set(zip(val_split.blocks, val_split.addresses))
    test_keys = set(zip(test_split.blocks, test_split.addresses))

    train_val_overlap = train_keys.intersection(val_keys)
    if train_val_overlap:
        raise DataLeakageError(f"Sample leakage detected between train and val: {len(train_val_overlap)} overlapping keys.")

    val_test_overlap = val_keys.intersection(test_keys)
    if val_test_overlap:
        raise DataLeakageError(f"Sample leakage detected between val and test: {len(val_test_overlap)} overlapping keys.")

    train_test_overlap = train_keys.intersection(test_keys)
    if train_test_overlap:
        raise DataLeakageError(f"Sample leakage detected between train and test: {len(train_test_overlap)} overlapping keys.")

    return True


def chronological_split(
    features: Any,
    addresses: Sequence[str],
    blocks: Sequence[int],
    labels: Sequence[int],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
) -> tuple[DatasetSplit, DatasetSplit, DatasetSplit]:
    """Partitions dataset chronologically by block boundaries.

    Ensures that no single block is split across partitions, preventing lookahead leakage.
    """
    n_samples = len(blocks)
    if n_samples == 0:
        empty_feat = np.empty((0, 10)) if HAS_NUMPY else []
        return (
            DatasetSplit(empty_feat, [], [], []),
            DatasetSplit(empty_feat, [], [], []),
            DatasetSplit(empty_feat, [], [], []),
        )

    # Sort indices chronologically by block
    sorted_indices = sorted(range(n_samples), key=lambda i: blocks[i])
    sorted_blocks = [blocks[i] for i in sorted_indices]

    # Target index cutoffs
    target_train_idx = max(int(train_ratio * n_samples), 1)
    target_val_idx = min(target_train_idx + max(int(val_ratio * n_samples), 1), n_samples - 1)

    # Align cutoffs to block boundaries
    unique_blocks = sorted(list(set(sorted_blocks)))
    if len(unique_blocks) >= 3:
        n_ub = len(unique_blocks)
        ub_train_idx = max(int(train_ratio * n_ub) - 1, 0)
        ub_val_idx = min(ub_train_idx + max(int(val_ratio * n_ub), 1), n_ub - 2)
        b_train_max = unique_blocks[ub_train_idx]
        b_val_max = unique_blocks[ub_val_idx]
    else:
        # Fallback for very few blocks
        b_train_max = unique_blocks[0]
        b_val_max = unique_blocks[min(1, len(unique_blocks)-1)]

    train_idx = [i for i in sorted_indices if blocks[i] <= b_train_max]
    val_idx = [i for i in sorted_indices if b_train_max < blocks[i] <= b_val_max]
    test_idx = [i for i in sorted_indices if blocks[i] > b_val_max]

    # If any set is empty due to small unique blocks, fallback to strictly index-based block partition
    if not val_idx and test_idx:
        val_idx = [test_idx.pop(0)]
    if not test_idx and len(val_idx) > 1:
        test_idx = [val_idx.pop(-1)]

    def make_split(indices: list[int]) -> DatasetSplit:
        if HAS_NUMPY and isinstance(features, np.ndarray):
            sub_feats = features[indices]
        else:
            sub_feats = [features[i] for i in indices]
        sub_labels = [labels[i] for i in indices]
        sub_addrs = [addresses[i] for i in indices]
        sub_blocks = [blocks[i] for i in indices]
        return DatasetSplit(sub_feats, sub_labels, sub_addrs, sub_blocks)

    train_split = make_split(train_idx)
    val_split = make_split(val_idx)
    test_split = make_split(test_idx)

    validate_no_data_leakage(train_split, val_split, test_split)
    return train_split, val_split, test_split


class RobustFeatureScaler:
    """Robust feature scaler based on median and interquartile range (IQR).

    Guarantees:
    - Pure-Python & NumPy dual compatibility.
    - Fitted strictly on training set statistics.
    - Zero division safely returns 0.0 or scales by 1.0.
    """

    def __init__(self):
        self.medians: list[float] = []
        self.iqrs: list[float] = []
        self.is_fitted: bool = False

    def fit(self, X: Any) -> RobustFeatureScaler:
        """Computes per-feature medians and IQRs on X_train."""
        if HAS_NUMPY and isinstance(X, np.ndarray):
            data = X.tolist()
        else:
            data = list(X)

        if not data:
            self.medians = [0.0] * 10
            self.iqrs = [1.0] * 10
            self.is_fitted = True
            return self

        n_features = len(data[0])
        self.medians = [0.0] * n_features
        self.iqrs = [1.0] * n_features

        for j in range(n_features):
            col = sorted(row[j] for row in data)
            n = len(col)
            # Median
            med = col[n // 2] if n % 2 != 0 else (col[n // 2 - 1] + col[n // 2]) / 2.0
            # Q1 (25th percentile) and Q3 (75th percentile)
            q1 = col[n // 4]
            q3 = col[(3 * n) // 4]
            iqr = q3 - q1
            self.medians[j] = float(med)
            self.iqrs[j] = float(iqr) if iqr > 1e-6 else 1.0

        self.is_fitted = True
        return self

    def transform(self, X: Any) -> Any:
        """Transforms input features using fitted statistics."""
        if not self.is_fitted:
            raise ValueError("RobustFeatureScaler is not fitted yet.")

        if HAS_NUMPY and isinstance(X, np.ndarray):
            med_arr = np.array(self.medians)
            iqr_arr = np.array(self.iqrs)
            return (X - med_arr) / iqr_arr

        res: list[list[float]] = []
        for row in X:
            scaled_row = [
                (float(row[j]) - self.medians[j]) / self.iqrs[j]
                for j in range(len(self.medians))
            ]
            res.append(scaled_row)
        return res

    def fit_transform(self, X: Any) -> Any:
        return self.fit(X).transform(X)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "RobustFeatureScaler",
            "medians": [round(m, 6) for m in self.medians],
            "iqrs": [round(iqr, 6) for iqr in self.iqrs],
            "is_fitted": self.is_fitted,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RobustFeatureScaler:
        scaler = cls()
        scaler.medians = [float(x) for x in data.get("medians", [])]
        scaler.iqrs = [float(x) for x in data.get("iqrs", [])]
        scaler.is_fitted = bool(data.get("is_fitted", True))
        return scaler
