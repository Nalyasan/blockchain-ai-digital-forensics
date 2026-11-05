"""Milestone M2 Comprehensive Remediation Verification Test Suite.

Verifies:
- Token decimals & unit-safe volumetric calculation (tokens.py).
- Ground truth label decoupling and window-scoped attack mapping (ground_truth.py, features.py).
- Scaler leakage prevention, isolation checking, and dataset manifest (dataset.py, manifest.py).
- Model architecture, He initialization, dying ReLU mitigation, and active neuron checking (model.py).
- Dual-engine PyTorch vs ONNX equivalence <= 1e-5 and unified inference engine (infer.py, registry.py).
- Local quantitative XAI metrics: fidelity R^2 >= 0.80, stability >= 0.85, and NOT_EXPLAINABLE fallback (xai.py).
- Grounded MITRE ATT&CK mapping: tactic_id, required_evidence, versioning, and NOT_MAPPED abstain (mitre.py, schemas.py).
"""
from __future__ import annotations

import math
from pathlib import Path
import sqlite3
from typing import Any
import pytest
from pydantic import ValidationError

from forensics.paths import REAL_P4_DB
from forensics.ml.tokens import (
    KNOWN_TOKEN_DECIMALS,
    normalize_token_amount_raw,
    compute_transfer_usd_value,
    get_token_decimals,
    get_reference_usd_price,
)
from forensics.ml.ground_truth import (
    CANONICAL_ATTACK_REGISTRY,
    IndependentGroundTruthRegistry,
    AttackIncidentRecord,
)
from forensics.ml.features import (
    FEATURE_NAMES,
    compute_features_for_transfers,
    extract_address_features,
    extract_single_address_features,
)
from forensics.ml.dataset import (
    DatasetSplit,
    RobustFeatureScaler,
    DataLeakageError,
    chronological_split,
    validate_no_data_leakage,
    verify_scaler_isolation,
    MLDatasetPipeline,
    grouped_by_incident_split,
)
from forensics.ml.manifest import (
    DATASET_MANIFEST_SCHEMA,
    compute_file_sha256,
    generate_dataset_manifest,
    validate_dataset_manifest,
)
from forensics.ml.model import (
    CompactAnomalyMLP,
    check_active_neurons,
    train_anomaly_detector,
    load_default_model,
    HAS_TORCH,
)
from forensics.ml.infer import (
    InferenceRecord,
    ForensicMLInferenceEngine,
)
from forensics.ml.registry import (
    export_to_onnx,
    verify_model_integrity,
    verify_pytorch_onnx_equivalence,
)
from forensics.ml.xai import (
    ExactShapleyExplainer,
    XAIExplanation,
    compute_local_fidelity,
    compute_local_stability,
    explain_instance,
)
from forensics.ml.mitre import (
    MITRE_DEFI_TAXONOMY,
    MitreMappingEngine,
    MitreAttackMapping as DataclassMitreMapping,
    UnsubstantiatedMappingError,
)
from forensics.ai.schemas import MitreAttackMapping as PydanticMitreMapping
from forensics.ai.ref_checker import check_investigation_output


# =====================================================================
# 1. Token Decimals & Unit-Safe Asset Valuation (tokens.py & features.py)
# =====================================================================

class TestTokenDecimalsAndUnitSafeFeatures:
    """Verifies token decimals normalization and unit-safe cross-asset volume."""

    def test_token_decimals_lookup(self):
        # 18 decimals
        assert get_token_decimals("NATIVE") == 18
        assert get_token_decimals("0x6b175474e89094c44da98b954eedeac495271d0f") == 18  # DAI
        assert get_token_decimals("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2") == 18  # WETH
        # 6 decimals
        assert get_token_decimals("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") == 6  # USDC
        assert get_token_decimals("0xdac17f958d2ee523a2206206994597c13d831ec7") == 6  # USDT
        # 8 decimals
        assert get_token_decimals("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599") == 8  # WBTC

    def test_normalize_token_amount_raw(self):
        # 1 USDC = 1,000,000 raw micro-units
        assert normalize_token_amount_raw("1000000", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") == 1.0
        # 1 ETH = 10^18 wei
        assert normalize_token_amount_raw("1000000000000000000", "NATIVE") == 1.0
        # 1 WBTC = 10^8 satoshis
        assert normalize_token_amount_raw("100000000", "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599") == 1.0

    def test_reference_usd_valuation(self):
        # 1 ETH @ $2000
        val_eth = compute_transfer_usd_value("1000000000000000000", "NATIVE")
        assert val_eth == 2000.0
        # 100 USDC @ $1.00
        val_usdc = compute_transfer_usd_value("100000000", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
        assert val_usdc == 100.0
        # 1 WBTC @ $30,000
        val_wbtc = compute_transfer_usd_value("100000000", "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599")
        assert val_wbtc == 30000.0

    def test_unit_safe_pass_through_ratio(self):
        """Swapping 10M DAI for 10M USDC must yield pass_through_ratio ~ 1.0, not 1e-12."""
        dai_in = {
            "block_number": 100,
            "from_addr": "0x1111111111111111111111111111111111111111",
            "to_addr": "0x2222222222222222222222222222222222222222",
            "asset_id": "0x6b175474e89094c44da98b954eedeac495271d0f",  # 18-dec DAI
            "amount_raw": str(10_000_000 * 10**18),
        }
        usdc_out = {
            "block_number": 101,
            "from_addr": "0x2222222222222222222222222222222222222222",
            "to_addr": "0x3333333333333333333333333333333333333333",
            "asset_id": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # 6-dec USDC
            "amount_raw": str(10_000_000 * 10**6),
        }
        feats = compute_features_for_transfers("0x2222222222222222222222222222222222222222", [dai_in, usdc_out])
        feat_dict = dict(zip(FEATURE_NAMES, feats))
        # pass_through_ratio should be very close to 1.0 (10M / (10M + 1))
        assert 0.99 <= feat_dict["pass_through_ratio"] <= 1.01
        assert feat_dict["max_single_out_ratio"] == 1.0


# =====================================================================
# 2. Independent Ground Truth & Window-Scoped Labels (ground_truth.py)
# =====================================================================

class TestGroundTruthAndDecoupling:
    """Verifies label decoupling and window-scoped attacker mapping."""

    def test_canonical_incident_registry(self):
        assert len(CANONICAL_ATTACK_REGISTRY) >= 2
        euler = next(inc for inc in CANONICAL_ATTACK_REGISTRY if inc.incident_id == "euler_finance_exploit")
        curve = next(inc for inc in CANONICAL_ATTACK_REGISTRY if inc.incident_id == "curve_aleth_vyper_reentrancy")
        assert "0xebc29199c817dc47ba12e3f86102564d640cbf99" in euler.attacker_entities
        assert "0xb657b895b265c38c53fff00166cf7f6a3c70587d" in curve.attacker_entities

    def test_window_scoped_labeling_euler(self):
        reg = IndependentGroundTruthRegistry()
        euler_attacker = "0xebc29199c817dc47ba12e3f86102564d640cbf99"
        # Pre-exploit window (block 16,816,000): must be 0
        assert reg.is_malicious_in_window(euler_attacker, 16816000, 16816100) == 0
        # Active exploit window (block 16,818,000): must be 1
        assert reg.is_malicious_in_window(euler_attacker, 16818000, 16818100) == 1
        # Post-exploit window (block 17,000,000): must be 0
        assert reg.is_malicious_in_window(euler_attacker, 17000000, 17000100) == 0
        # Innocent address: must always be 0
        assert reg.is_malicious_in_window("0x000000000000000000000000000000000000dead", 16818000, 16818100) == 0

    def test_decoupled_feature_extraction_on_real_db(self):
        """Extracts features from real_p4.db and confirms labels are decoupled and window-scoped."""
        res = extract_address_features(REAL_P4_DB)
        assert len(res.features) > 0
        # Positive labels must reflect verified exploit windows (around 12), not 979
        pos_count = sum(res.labels)
        assert 5 <= pos_count <= 25, f"Expected 5-25 positive samples, got {pos_count}"


# =====================================================================
# 3. Scaler Leakage Prevention & Dataset Manifest (dataset.py & manifest.py)
# =====================================================================

class TestScalerLeakageAndDatasetManifest:
    """Verifies scaler isolation and dataset manifest generation."""

    def test_verify_scaler_isolation_passes_on_train_only(self):
        train = DatasetSplit([[1.0, 2.0], [3.0, 4.0]], [0, 1], ["0x1", "0x2"], [100, 101])
        val = DatasetSplit([[5.0, 6.0]], [0], ["0x3"], [200])
        test = DatasetSplit([[7.0, 8.0]], [0], ["0x4"], [300])

        scaler = RobustFeatureScaler().fit(train.features)
        assert verify_scaler_isolation(scaler, train, val, test) is True

    def test_verify_scaler_isolation_detects_leakage(self):
        train = DatasetSplit([[1.0, 2.0], [3.0, 4.0]], [0, 1], ["0x1", "0x2"], [100, 101])
        val = DatasetSplit([[5.0, 6.0]], [0], ["0x3"], [200])
        test = DatasetSplit([[7.0, 8.0]], [0], ["0x4"], [300])

        # Leaked scaler fit on train + test
        leaked_scaler = RobustFeatureScaler().fit(train.features + test.features)
        with pytest.raises(DataLeakageError):
            verify_scaler_isolation(leaked_scaler, train, val, test)

    def test_ml_dataset_pipeline_prepare(self):
        features = [[float(i), float(i * 2)] for i in range(100)]
        addresses = [f"0x{i:040x}" for i in range(100)]
        blocks = [1000 + i * 10 for i in range(100)]
        labels = [1 if i % 10 == 0 else 0 for i in range(100)]

        pipeline = MLDatasetPipeline(train_ratio=0.70, val_ratio=0.15, test_ratio=0.15)
        prepared = pipeline.prepare(features, addresses, blocks, labels)

        assert len(prepared.train) > 0
        assert len(prepared.val) > 0
        assert len(prepared.test) > 0
        assert prepared.scaler.is_fitted
        assert len(prepared.provenance_digest) == 64

    def test_grouped_by_incident_split(self):
        features = [[1.0] * 10 for _ in range(6)]
        addresses = ["0xa", "0xb", "0xc", "0xd", "0xe", "0xf"]
        blocks = [16817500, 16818000, 17000000, 17500000, 17810000, 17850000]
        labels = [1, 1, 0, 0, 1, 1]

        train_s, val_s, test_s = grouped_by_incident_split(
            features, addresses, blocks, labels,
            train_incident_blocks=(16817000, 16819000),
            test_incident_blocks=(17800000, 17860000),
        )
        assert len(train_s) == 2  # Euler blocks
        assert len(val_s) == 2    # Intermediate blocks
        assert len(test_s) == 2   # Curve blocks


# =====================================================================
# 4. Model Architecture & Dual-Engine Equivalence (model.py & infer.py)
# =====================================================================

class TestModelArchitectureAndDualSync:
    """Verifies He initialization, active neurons, and PyTorch-ONNX equivalence."""

    def test_he_uniform_initialization_bounds(self):
        model = CompactAnomalyMLP(init_method="he", seed=42)
        # Layer 1: fan_in=10 -> bound = sqrt(6/10) ~ 0.7746
        bound1 = math.sqrt(6.0 / 10.0)
        for row in model.w1:
            for val in row:
                assert -bound1 <= val <= bound1

        # Layer 2: fan_in=16 -> bound = sqrt(6/16) ~ 0.6124
        bound2 = math.sqrt(6.0 / 16.0)
        for row in model.w2:
            for val in row:
                assert -bound2 <= val <= bound2

        # Positive bias initialization
        assert all(b == 0.01 for b in model.b1)
        assert all(b == 0.01 for b in model.b2)
        assert model.count_parameters() == 321

    def test_check_active_neurons_healthy(self):
        model = CompactAnomalyMLP(init_method="he", seed=42)
        samples = [[float(j) for j in range(10)] for _ in range(50)]
        diag = check_active_neurons(model, samples)
        assert diag["is_healthy"] is True
        assert diag["layer1_active_ratio"] >= 0.10
        assert diag["layer2_active_ratio"] >= 0.10

    @pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not available")
    def test_pytorch_onnx_equivalence(self, tmp_path):
        from forensics.ml.model import PyTorchAnomalyMLP
        import numpy as np

        model = CompactAnomalyMLP(model_id="sync_test", init_method="he", seed=42)
        tm = PyTorchAnomalyMLP()
        tm.load_from_compact_mlp(model)

        onnx_file = tmp_path / "sync_test.onnx"
        export_to_onnx(model, onnx_file)

        np.random.seed(42)
        test_vectors = np.random.uniform(-5.0, 5.0, size=(100, 10)).tolist()

        is_equiv, max_err = verify_pytorch_onnx_equivalence(
            model=tm,
            onnx_path=onnx_file,
            test_vectors=test_vectors,
            float_tolerance=1e-5,
        )
        assert is_equiv is True
        assert max_err <= 1e-5

    def test_inference_engine_record(self):
        engine = ForensicMLInferenceEngine()
        test_vec = [1.0, 2.0, 3.0, 4.0, 5.0, 0.5, 2.0, 1.0, 0.5, 0.8]
        rec = engine.predict(test_vec, evidence_refs=["tx:0x" + "a"*64])
        assert isinstance(rec, InferenceRecord)
        assert rec.inference_id.startswith("inf_")
        assert len(rec.input_digest) == 64
        assert rec.float_tolerance_verified is True
        d = rec.to_dict()
        assert "prediction_score" in d


# =====================================================================
# 5. Local Quantitative XAI Metrics (xai.py)
# =====================================================================

class TestQuantitativeXAIMetrics:
    """Verifies local fidelity R^2, stability, and NOT_EXPLAINABLE fallback."""

    def test_local_fidelity_metrics(self):
        model = CompactAnomalyMLP(init_method="he", seed=42)
        explainer = ExactShapleyExplainer(
            model_predict_fn=model.forward_single,
            baseline_vector=[0.0] * 10,
        )
        x = [2.0, 1.0, 1.0, 23.14, 23.14, 1.0, 1.0, 0.0, 0.0, 1.0]
        exp = explainer.explain(x, evaluate_metrics=True)

        assert exp.is_explainable is True
        assert exp.status == "EXPLAINABLE"
        assert exp.reconstruction_error <= 0.05
        assert exp.fidelity_r2 >= 0.80

    def test_local_stability_score(self):
        model = CompactAnomalyMLP(init_method="he", seed=42)
        explainer = ExactShapleyExplainer(
            model_predict_fn=model.forward_single,
            baseline_vector=[0.0] * 10,
        )
        x = [5.0, 2.0, 3.0, 20.0, 18.0, 0.9, 2.0, 1.0, 0.5, 1.0]
        exp = explainer.explain(x, evaluate_metrics=True)

        assert exp.stability_score >= 0.85

    def test_not_explainable_on_degenerate_input(self):
        model = CompactAnomalyMLP()
        explainer = ExactShapleyExplainer(model_predict_fn=model.forward_single)
        nan_input = [float("nan")] * 10
        exp = explainer.explain(nan_input, evaluate_metrics=True)

        assert exp.is_explainable is False
        assert exp.status == "NOT_EXPLAINABLE"
        assert "NaN or Infinite" in exp.abstain_reason


# =====================================================================
# 6. MITRE ATT&CK Grounded Mapping & Abstain Mechanism (mitre.py & schemas.py)
# =====================================================================

class TestGroundedMitreMappingAndAbstain:
    """Verifies MITRE grounding, tactic_id, required_evidence, and abstain logic."""

    def test_taxonomy_completeness(self):
        for tid, defn in MITRE_DEFI_TAXONOMY.items():
            assert defn.tactic_id.startswith("TA")
            assert len(defn.mapping_version) > 0
            assert len(defn.mapping_rule) > 0
            if tid != "NOT_MAPPED":
                assert len(defn.required_evidence) >= 2
                assert "canonical_evidence_ref" in defn.required_evidence
                assert defn.reference_url.startswith("https://attack.mitre.org/")

    def test_mapped_technique_carries_tactic_id(self):
        engine = MitreMappingEngine(strict_evidence=True)
        valid_ref = "tx:0x" + "5"*64
        mappings = engine.map_anomaly(
            features={
                "tx_velocity": 6.0,
                "volume_in_normalized": 12.0,
                "volume_out_normalized": 12.0,
                "token_diversity": 2.0,
                "turnover_latency_min": 0.0,
            },
            anomaly_score=0.88,
            rule_alerts=[{"rule_id": "large_transfer", "alert_id": "e"*64, "evidence_refs": []}],
            evidence_refs=[valid_ref],
        )
        assert len(mappings) >= 1
        t1565 = next(m for m in mappings if m["technique_id"] == "T1565.001")
        assert t1565["tactic_id"] == "TA0040"
        assert t1565["mapping_rule"] == "FLASH_LOAN_ORACLE_DISTORTION"
        assert "canonical_evidence_ref" in t1565["required_evidence"]
        assert t1565["analyst_review_status"] == "MACHINE_SUGGESTED"

    def test_fail_safe_abstain_on_normal_behavior(self):
        engine = MitreMappingEngine(strict_evidence=True, fallback_to_abstain=True)
        valid_ref = "tx:0x" + "a"*64
        mappings = engine.map_anomaly(
            features={"tx_velocity": 0.5, "max_single_out_ratio": 0.1},
            anomaly_score=0.12,
            rule_alerts=[],
            evidence_refs=[valid_ref],
        )
        assert len(mappings) == 1
        m = mappings[0]
        assert m["technique_id"] == "NOT_MAPPED"
        assert m["tactic_id"] == "TA0000"
        assert m["confidence"] == 0.0
        assert m["analyst_review_status"] == "ABSTAINED"
        assert m["mapping_rule"] == "ABSTAIN_NORMAL_BEHAVIOR"

    def test_pydantic_schema_validates_both_mapped_and_abstain_records(self):
        # 1. Valid mapped technique
        m_mapped = PydanticMitreMapping(
            technique_id="T1566.002",
            technique_name="Phishing: Spearphishing Link",
            tactic="Initial Access",
            tactic_id="TA0001",
            confidence=0.85,
            evidence_refs=["tx:0x" + "1"*64],
            rationale="Drained via approval scam",
            required_evidence=["canonical_evidence_ref"],
            mapping_rule="R1_LARGE_TRANSFER_OR_SINGLE_OUT_BURST",
        )
        assert m_mapped.tactic_id == "TA0001"

        # 2. Valid abstain technique (allows empty evidence_refs)
        m_abstain = PydanticMitreMapping(
            technique_id="NOT_MAPPED",
            technique_name="Unmapped Activity / Abstain",
            tactic="Unmapped",
            tactic_id="TA0000",
            confidence=0.0,
            evidence_refs=[],
            rationale="No technique met required evidence",
            mapping_rule="ABSTAIN_INSUFFICIENT_CRITERIA",
            analyst_review_status="ABSTAINED",
        )
        assert m_abstain.technique_id == "NOT_MAPPED"
        assert m_abstain.confidence == 0.0

        # 3. Mapped technique with empty evidence_refs must fail
        with pytest.raises(ValidationError):
            PydanticMitreMapping(
                technique_id="T1027",
                technique_name="Obfuscation",
                tactic="Defense Evasion",
                tactic_id="TA0005",
                confidence=0.8,
                evidence_refs=[],
                rationale="Empty evidence violation",
            )
