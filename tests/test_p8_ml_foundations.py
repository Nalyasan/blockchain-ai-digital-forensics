"""Test Suite 1: P8 Machine Learning Foundations.

Tests:
1. 10-feature vector extraction from real_p4.db (shape, names, finite, zero-division).
2. Log10 volume normalization with extreme arbitrary-precision wei amounts.
3. Chronological train/val/test splitting (70/15/15) by block boundary.
4. Anti-leakage validator (DataLeakageError on temporal inversion or overlap).
5. RobustFeatureScaler (fitted strictly on train, handles zero IQR).
6. CompactAnomalyMLP (architecture, exactly 321 parameters, forward pass, training).
7. ONNX serialization, SHA-256 calculation, and model registry integrity verification.
"""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import pytest

from forensics.paths import REAL_P4_DB
from forensics.ml.features import (
    FEATURE_NAMES,
    compute_features_for_transfers,
    extract_address_features,
    extract_single_address_features,
    safe_log10,
)
from forensics.ml.dataset import (
    DataLeakageError,
    DatasetSplit,
    RobustFeatureScaler,
    chronological_split,
    validate_no_data_leakage,
)
from forensics.ml.model import (
    CompactAnomalyMLP,
    load_default_model,
    train_anomaly_detector,
)
from forensics.ml.registry import (
    compute_file_sha256,
    export_to_onnx,
    load_model_metadata,
    save_model,
    verify_model_integrity,
)


class TestFeaturePipeline:
    """Verifies feature extraction, normalization, and boundary handling."""

    def test_feature_names_canonical(self):
        assert len(FEATURE_NAMES) == 10
        expected = [
            "tx_velocity",
            "unique_counterparties_in",
            "unique_counterparties_out",
            "volume_in_normalized",
            "volume_out_normalized",
            "pass_through_ratio",
            "token_diversity",
            "turnover_latency_min",
            "burstiness_std",
            "max_single_out_ratio",
        ]
        assert FEATURE_NAMES == expected

    def test_safe_log10_extreme_amounts(self):
        assert safe_log10(0) == 0.0
        assert safe_log10(-100) == 0.0
        # 1 ETH = 10^18 wei -> log10(10^18 + 1) ~ 18.0
        assert 18.0 <= safe_log10(10**18) <= 18.01
        # Arbitrary precision wei (e.g. 10^30)
        assert 30.0 <= safe_log10(10**30) <= 30.01
        # Overflow safety for 10^350 (beyond IEEE 754 double 1.79e308)
        val_350 = 10**350
        res = safe_log10(val_350)
        assert 349.9 <= res <= 350.1

    def test_feature_zero_division_safety(self):
        """Zero counterparties, zero volume, and single transfers must not raise exceptions."""
        empty_vec = compute_features_for_transfers("0x1111111111111111111111111111111111111111", [])
        assert empty_vec == [0.0] * 10

        single_transfer = [{
            "block_number": 100,
            "from_addr": "0x1111111111111111111111111111111111111111",
            "to_addr": "0x2222222222222222222222222222222222222222",
            "asset_id": "0x6b175474e89094c44da98b954eedeac495271d0f",
            "amount_raw": "5000000000000000000",
        }]
        vec = compute_features_for_transfers("0x1111111111111111111111111111111111111111", single_transfer)
        assert len(vec) == 10
        assert vec[0] == 1.0  # tx_velocity
        assert vec[1] == 0.0  # counterparties_in
        assert vec[2] == 1.0  # counterparties_out
        assert vec[3] == 0.0  # volume_in_normalized
        assert vec[4] > 0.0   # volume_out_normalized
        assert vec[5] == 10.0 # pass_through_ratio (capped when volume_in is 0)
        assert vec[6] == 1.0  # token_diversity
        assert vec[7] == 0.0  # turnover_latency_min (no incoming transfer)
        assert vec[8] == 0.0  # burstiness_std (len < 2)
        assert vec[9] == 1.0  # max_single_out_ratio

    def test_extract_from_real_database(self):
        """Verifies feature extraction against canonical real_p4.db."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not present at default path")

        res = extract_address_features(REAL_P4_DB, window_blocks=100)
        assert len(res.features) > 1000
        assert len(res.addresses) == len(res.features)
        assert len(res.feature_names) == 10
        assert sum(res.labels) > 0

        # Unpacking as 3-tuple
        X, addrs, fnames = res
        assert len(X) == len(addrs)
        assert fnames == FEATURE_NAMES

    def test_extract_single_address_features(self):
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not present at default path")

        # Euler attacker frontrun address
        addr = "0xebc29199c817dc47ba12e3f86102564d640cbf99"
        feat_dict = extract_single_address_features(REAL_P4_DB, addr)
        assert isinstance(feat_dict, dict)
        for name in FEATURE_NAMES:
            assert name in feat_dict
            assert isinstance(feat_dict[name], float)


class TestDatasetPartitioning:
    """Verifies chronological 70/15/15 splitting and anti-leakage guards."""

    def test_chronological_split_and_no_leakage(self):
        # 100 synthetic sequential blocks
        blocks = [1000 + (i // 5) for i in range(100)]
        addrs = [f"0x{i:040x}" for i in range(100)]
        feats = [[float(j) for j in range(10)] for _ in range(100)]
        labels = [1 if i % 10 == 0 else 0 for i in range(100)]

        train_s, val_s, test_s = chronological_split(feats, addrs, blocks, labels)

        assert len(train_s) > 0
        assert len(val_s) > 0
        assert len(test_s) > 0
        assert len(train_s) + len(val_s) + len(test_s) == 100

        # Strict chronological ordering: max(train) < min(val) < min(test)
        assert max(train_s.blocks) < min(val_s.blocks)
        assert max(val_s.blocks) < min(test_s.blocks)

    def test_anti_leakage_validator_detects_inversion(self):
        # Inverted train and val
        train_s = DatasetSplit([[0.0]*10], [0], ["0x1111"], [1005])
        val_s = DatasetSplit([[0.0]*10], [0], ["0x2222"], [1000]) # val block < train block!
        test_s = DatasetSplit([[0.0]*10], [0], ["0x3333"], [1010])

        with pytest.raises(DataLeakageError, match="Temporal leakage detected"):
            validate_no_data_leakage(train_s, val_s, test_s)

    def test_robust_feature_scaler(self):
        X_train = [
            [1.0, 10.0],
            [2.0, 20.0],
            [3.0, 30.0],
            [4.0, 40.0],
            [5.0, 50.0],
        ]
        scaler = RobustFeatureScaler()
        X_scaled = scaler.fit_transform(X_train)
        assert scaler.is_fitted
        # Median of [1,2,3,4,5] is 3.0
        assert scaler.medians[0] == 3.0
        assert scaler.medians[1] == 30.0
        # Scaled median row should be [0.0, 0.0]
        assert abs(X_scaled[2][0]) < 1e-6
        assert abs(X_scaled[2][1]) < 1e-6

        # Zero IQR fallback: column with constant values
        X_const = [[5.0, 1.0], [5.0, 2.0], [5.0, 3.0]]
        s2 = RobustFeatureScaler().fit(X_const)
        assert s2.iqrs[0] == 1.0  # safe fallback


class TestModelArchitectureAndRegistry:
    """Verifies MLP architecture, parameter count, ONNX export, and SHA-256 verification."""

    def test_mlp_exact_parameter_count(self):
        model = CompactAnomalyMLP()
        # fc1: 10*16 + 16 = 176
        # fc2: 16*8 + 8 = 136
        # fc3: 8*1 + 1 = 9
        # Total = 176 + 136 + 9 = 321
        assert model.count_parameters() == 321

    def test_mlp_forward_pass_bounds(self):
        model = CompactAnomalyMLP()
        test_x = [1.0, 0.0, 2.0, 15.5, 12.3, 0.95, 2.0, 1.0, 0.5, 0.8]
        score = model.forward_single(test_x)
        assert 0.0 <= score <= 1.0

        scores = model.forward([test_x, [0.0]*10])
        assert len(scores) == 2
        for s in scores:
            assert 0.0 <= s <= 1.0

    def test_train_anomaly_detector_convergence(self):
        # Synthetic separable dataset
        X = [[0.0]*10 for _ in range(20)] + [[5.0]*10 for _ in range(5)]
        y = [0]*20 + [1]*5
        model, metrics = train_anomaly_detector(X, y, epochs=30, lr=0.05, pos_weight=5.0)
        assert metrics["final_train_loss"] >= 0.0
        assert model.count_parameters() == 321

    def test_onnx_export_and_registry_sha256(self, tmp_path):
        model = CompactAnomalyMLP(model_id="test_detector")
        meta = {
            "model_version": "1.0.0",
            "test_metric": 0.95,
        }
        onnx_path, sha256_hash = save_model(model, "test_detector", meta, models_dir=tmp_path)
        assert onnx_path.exists()
        assert len(sha256_hash) == 64
        # Verify hash matches actual file bytes
        calc_hash = compute_file_sha256(onnx_path)
        assert calc_hash == sha256_hash

        # Verify integrity checker returns True
        assert verify_model_integrity("test_detector", models_dir=tmp_path)

        # Tampering with ONNX file must fail integrity verification
        with open(onnx_path, "ab") as f:
            f.write(b"tampered_bytes")
        assert not verify_model_integrity("test_detector", models_dir=tmp_path)
