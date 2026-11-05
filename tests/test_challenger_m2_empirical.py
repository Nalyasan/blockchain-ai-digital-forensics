"""Empirical Adversarial Stress Test Suite for Milestone M2 Verification.

Author: challenger_v6_M2_1
Target Commit: 280aa3d (Milestone M2)
Specification: AGENT.md §6.1, §6.2, §6.3, Gates T08-T11, T14-T17

Stress Testing Dimensions:
1. Extreme Decimals & Boundary Values (uint256 max, 0, negative, malformed, unregistered tokens).
2. Scaler Leakage Adversarial Probes & Invariant Testing under Test Distribution Perturbations.
3. Multi-Window Address Isolation & Cross-Incident Non-Contamination Probes.
4. ONNX vs PyTorch Dual-Engine 1,000 Random/Adversarial Vector Equivalence Test (tolerance <= 1e-5).
5. Canonical Database Bitwise Invariance Assertions (real_p4.db, forensics.db, benchmark_p6.db, .env).
"""
from __future__ import annotations

import copy
import hashlib
import math
from pathlib import Path
import random
import sqlite3
import pytest

from forensics.ml.tokens import (
    DEFAULT_TOKEN_DECIMALS,
    DEFAULT_USD_PRICE,
    KNOWN_TOKEN_DECIMALS,
    REFERENCE_USD_PRICES,
    compute_transfer_usd_value,
    get_reference_usd_price,
    get_token_decimals,
    normalize_token_amount_raw,
)
from forensics.ml.features import (
    FEATURE_NAMES,
    compute_features_for_transfers,
    extract_address_features,
)
from forensics.ml.ground_truth import (
    CANONICAL_ATTACK_REGISTRY,
    AttackIncidentRecord,
    IndependentGroundTruthRegistry,
)
from forensics.ml.dataset import (
    DataLeakageError,
    DatasetSplit,
    MLDatasetPipeline,
    RobustFeatureScaler,
    chronological_split,
    grouped_by_incident_split,
    validate_no_data_leakage,
    verify_scaler_isolation,
)
from forensics.ml.model import CompactAnomalyMLP, PyTorchAnomalyMLP, check_active_neurons
from forensics.ml.infer import ForensicMLInferenceEngine, InferenceRecord
from forensics.ml.registry import verify_pytorch_onnx_equivalence
from forensics.ml.xai import (
    ExactShapleyExplainer,
    compute_local_fidelity,
    compute_local_stability,
)
from forensics.ml.mitre import (
    MITRE_DEFI_TAXONOMY,
    MitreMappingEngine,
    UnsubstantiatedMappingError,
)
from forensics.paths import accepted_env_sha256


CANONICAL_HASHES = {
    "real_p4.db": "6bd9aed48ac2742d0862198bff65994861244ec681dc8abeb3e6f771e7808c97",
    "forensics.db": "3f2b0dfc772a96ff6ea57c65807b5b6b9a20fcf74c409c6f222fcff29f1ef001",
    "benchmark_p6.db": "c7ff724cd214eef57e58a6fbe44dbeb2712c54b035907b2a6279a255c0e80507",
    ".env": "c2f4879666cd21276c58ec75de923c8235d414f3d646a854a835c5638ec1699c",
}

ROOT_DIR = Path(__file__).resolve().parents[1]


def _compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


# =====================================================================
# Dimension 1: Extreme Decimals & Boundary Values
# =====================================================================

class TestAdversarialExtremeDecimals:
    """Stress tests token decimals, boundary values, and volumetric valuation."""

    def test_uint256_max_raw_amount_normalization(self):
        """Stress test with 2^256 - 1 (EVM max uint256)."""
        uint256_max = (1 << 256) - 1
        uint256_max_str = str(uint256_max)

        # 18-decimal token (WETH)
        weth_norm = normalize_token_amount_raw(uint256_max_str, "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
        expected_weth = float(uint256_max) / 1e18
        assert math.isclose(weth_norm, expected_weth, rel_tol=1e-12)
        assert weth_norm > 1e59

        # 6-decimal token (USDC)
        usdc_norm = normalize_token_amount_raw(uint256_max, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
        expected_usdc = float(uint256_max) / 1e6
        assert math.isclose(usdc_norm, expected_usdc, rel_tol=1e-12)
        assert usdc_norm > 1e71

        # 8-decimal token (WBTC)
        wbtc_norm = normalize_token_amount_raw(uint256_max_str, "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599")
        expected_wbtc = float(uint256_max) / 1e8
        assert math.isclose(wbtc_norm, expected_wbtc, rel_tol=1e-12)

    def test_zero_and_negative_amounts(self):
        """Stress test zero, negative, and boundary signed values."""
        token = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
        assert normalize_token_amount_raw(0, token) == 0.0
        assert normalize_token_amount_raw("0", token) == 0.0
        assert normalize_token_amount_raw("00000000", token) == 0.0
        assert normalize_token_amount_raw(-1, token) == 0.0
        assert normalize_token_amount_raw("-1000000000000000000", token) == 0.0
        assert normalize_token_amount_raw(-(1 << 255), token) == 0.0

    def test_malformed_and_edge_inputs(self):
        """Stress test malformed strings, floats, non-integers, and None."""
        token = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        assert normalize_token_amount_raw("not_a_number", token) == 0.0
        assert normalize_token_amount_raw("12.345", token) == 0.0  # raw amount must be integer
        assert normalize_token_amount_raw("1e18", token) == 0.0
        assert normalize_token_amount_raw("0x10", token) == 0.0
        assert normalize_token_amount_raw("", token) == 0.0
        assert normalize_token_amount_raw(None, token) == 0.0  # type: ignore
        assert normalize_token_amount_raw([], token) == 0.0    # type: ignore
        assert normalize_token_amount_raw({}, token) == 0.0    # type: ignore

    def test_unregistered_and_case_insensitive_tokens(self):
        """Stress test unregistered token symbols and case variation."""
        # Unregistered token must safely default to 18 decimals and 1.0 USD
        unregistered = "0x9999999999999999999999999999999999999999"
        assert get_token_decimals(unregistered) == DEFAULT_TOKEN_DECIMALS
        assert get_reference_usd_price(unregistered) == DEFAULT_USD_PRICE
        norm = normalize_token_amount_raw("1000000000000000000", unregistered)
        assert norm == 1.0

        # Case-insensitivity: USDC uppercase address
        usdc_upper = "0xA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48"
        assert get_token_decimals(usdc_upper) == 6
        assert get_reference_usd_price(usdc_upper) == 1.0
        assert normalize_token_amount_raw("1000000", usdc_upper) == 1.0

    def test_prevent_cross_scale_volume_distortion(self):
        """Verify that direct raw addition across assets produces massive error,
        while compute_transfer_usd_value produces unit-safe aggregation.
        """
        weth_raw = 10 * 10**18     # 10 WETH ($20,000)
        usdc_raw = 20_000 * 10**6  # 20,000 USDC ($20,000)
        wbtc_raw = 1 * 10**8       # 1 WBTC ($30,000)

        # Naive raw sum would be dominated entirely by WETH (10^19 >> 10^10 >> 10^8)
        raw_sum = weth_raw + usdc_raw + wbtc_raw
        assert raw_sum == 10000000020100000000
        # Notice that WETH accounts for >99.99999% of naive raw sum despite USDC and WBTC having equal/greater USD value
        assert raw_sum / weth_raw > 0.99999999

        # Economically grounded USD valuation
        usd_weth = compute_transfer_usd_value(weth_raw, "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
        usd_usdc = compute_transfer_usd_value(usdc_raw, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
        usd_wbtc = compute_transfer_usd_value(wbtc_raw, "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599")

        assert math.isclose(usd_weth, 20_000.0)
        assert math.isclose(usd_usdc, 20_000.0)
        assert math.isclose(usd_wbtc, 30_000.0)
        total_usd = usd_weth + usd_usdc + usd_wbtc
        assert math.isclose(total_usd, 70_000.0)


# =====================================================================
# Dimension 2: Scaler Leakage Adversarial Probes
# =====================================================================

class TestAdversarialScalerLeakage:
    """Stress tests scaler isolation, leakage detection, and invariance under test perturbation."""

    def test_scaler_isolation_fails_when_test_injected_into_scaler(self):
        """Adversarially inject test split features into scaler fitting and assert DataLeakageError."""
        train = DatasetSplit(
            features=[[10.0, 20.0], [30.0, 40.0], [50.0, 60.0]],
            labels=[0, 0, 1],
            addresses=["0x1", "0x2", "0x3"],
            blocks=[100, 101, 102],
        )
        val = DatasetSplit(
            features=[[70.0, 80.0]],
            labels=[0],
            addresses=["0x4"],
            blocks=[200],
        )
        test = DatasetSplit(
            features=[[500.0, 600.0], [700.0, 800.0]],
            labels=[1, 1],
            addresses=["0x5", "0x6"],
            blocks=[300, 301],
        )

        # Clean scaler
        clean_scaler = RobustFeatureScaler().fit(train.features)
        assert verify_scaler_isolation(clean_scaler, train, val, test) is True

        # Leaked scaler: fit on train + test
        leaked_scaler = RobustFeatureScaler().fit(train.features + test.features)
        with pytest.raises(DataLeakageError) as exc_info:
            verify_scaler_isolation(leaked_scaler, train, val, test)
        assert "Scaler leakage detected" in str(exc_info.value)

    def test_train_scaler_invariance_under_extreme_test_perturbation(self):
        """Verify that training scaler parameters are completely invariant to any
        adversarial perturbations applied to the test split.
        """
        train = DatasetSplit(
            features=[[float(i), float(i * 3)] for i in range(1, 21)],
            labels=[0] * 18 + [1, 1],
            addresses=[f"0x{i:x}" for i in range(1, 21)],
            blocks=[1000 + i for i in range(1, 21)],
        )
        val = DatasetSplit(
            features=[[100.0, 300.0], [105.0, 315.0]],
            labels=[0, 0],
            addresses=["0xval1", "0xval2"],
            blocks=[2000, 2001],
        )
        test_base = DatasetSplit(
            features=[[200.0, 600.0], [210.0, 630.0]],
            labels=[0, 1],
            addresses=["0xtest1", "0xtest2"],
            blocks=[3000, 3001],
        )

        scaler = RobustFeatureScaler().fit(train.features)
        initial_medians = list(scaler.medians)
        initial_iqrs = list(scaler.iqrs)

        # Adversarially perturb test split by 10,000x and inject massive outliers
        adversarial_test = DatasetSplit(
            features=[[1e9, -1e9], [999999.0, 0.000001]],
            labels=[1, 1],
            addresses=["0xbad1", "0xbad2"],
            blocks=[3000, 3001],
        )

        # Scaler isolation check must still pass because scaler was fitted ONLY on train
        assert verify_scaler_isolation(scaler, train, val, adversarial_test) is True
        assert scaler.medians == initial_medians
        assert scaler.iqrs == initial_iqrs

    def test_temporal_leakage_detection(self):
        """Verify that chronological splitting fails-closed when future blocks contaminate train."""
        # Clean splits
        train = DatasetSplit([[1.0]], [0], ["0x1"], [100])
        val = DatasetSplit([[2.0]], [0], ["0x2"], [200])
        test = DatasetSplit([[3.0]], [0], ["0x3"], [300])
        assert validate_no_data_leakage(train, val, test) is True

        # Contaminated: train block 250 > val block 200
        train_leaked = DatasetSplit([[1.0], [1.5]], [0, 0], ["0x1", "0x1b"], [100, 250])
        with pytest.raises(DataLeakageError) as exc:
            validate_no_data_leakage(train_leaked, val, test)
        assert "Temporal leakage detected" in str(exc.value)

        # Contaminated: future blocks in test < val blocks triggers temporal leakage
        test_temporal_leaked = DatasetSplit([[3.0]], [0], ["0x1"], [100])
        with pytest.raises(DataLeakageError) as exc2:
            validate_no_data_leakage(train, val, test_temporal_leaked)
        assert "Temporal leakage detected" in str(exc2.value)

        # Contaminated: direct duplicate sample with empty val split triggers sample leakage check
        val_empty = DatasetSplit([], [], [], [])
        with pytest.raises(DataLeakageError) as exc3:
            validate_no_data_leakage(train, val_empty, test_temporal_leaked)
        assert "Sample leakage detected between train and test" in str(exc3.value)


# =====================================================================
# Dimension 3: Multi-Window Address Isolation Probe
# =====================================================================

class TestAdversarialAddressWindowIsolation:
    """Stress tests address labeling across isolated temporal windows."""

    def test_euler_attacker_strict_window_containment(self):
        """Attacker 0xebc29199c817dc47ba12e3f86102564d640cbf99 must be malicious
        ONLY during Euler exploit window [16817990, 16818110], and strictly benign elsewhere.
        """
        registry = IndependentGroundTruthRegistry()
        euler_attacker = "0xebc29199c817dc47ba12e3f86102564d640cbf99"

        # 1. Historical pre-exploit windows (far past, near past)
        assert registry.is_malicious_in_window(euler_attacker, 10000000, 10001000) == 0
        assert registry.is_malicious_in_window(euler_attacker, 16817000, 16817900) == 0
        assert registry.is_malicious_in_window(euler_attacker, 16817980, 16817989) == 0  # 1 block before

        # 2. Exact exploit boundary and overlapping intervals
        assert registry.is_malicious_in_window(euler_attacker, 16817990, 16818110) == 1  # exact
        assert registry.is_malicious_in_window(euler_attacker, 16818000, 16818050) == 1  # subset
        assert registry.is_malicious_in_window(euler_attacker, 16817900, 16818000) == 1  # left overlap
        assert registry.is_malicious_in_window(euler_attacker, 16818100, 16818200) == 1  # right overlap

        # 3. Post-exploit windows (near future, far future)
        assert registry.is_malicious_in_window(euler_attacker, 16818111, 16818200) == 0  # 1 block after
        assert registry.is_malicious_in_window(euler_attacker, 17000000, 17000100) == 0
        assert registry.is_malicious_in_window(euler_attacker, 20000000, 20000100) == 0

    def test_curve_attacker_strict_window_containment(self):
        """Attacker 0xb657b895b265c38c53fff00166cf7f6a3c70587d must be malicious
        ONLY during Curve exploit window [17806770, 17851010].
        """
        registry = IndependentGroundTruthRegistry()
        curve_attacker = "0xb657b895b265c38c53fff00166cf7f6a3c70587d"

        # Pre-exploit
        assert registry.is_malicious_in_window(curve_attacker, 16817990, 16818110) == 0
        assert registry.is_malicious_in_window(curve_attacker, 17800000, 17806769) == 0

        # Exploit window
        assert registry.is_malicious_in_window(curve_attacker, 17806770, 17851010) == 1
        assert registry.is_malicious_in_window(curve_attacker, 17810000, 17820000) == 1

        # Post-exploit
        assert registry.is_malicious_in_window(curve_attacker, 17851011, 17860000) == 0
        assert registry.is_malicious_in_window(curve_attacker, 19000000, 19001000) == 0

    def test_cross_incident_isolation_no_global_contamination(self):
        """Verify that Euler attacker is NOT labeled malicious during Curve exploit window,
        and Curve attacker is NOT labeled malicious during Euler exploit window.
        """
        registry = IndependentGroundTruthRegistry()
        euler_attacker = "0xebc29199c817dc47ba12e3f86102564d640cbf99"
        curve_attacker = "0xb657b895b265c38c53fff00166cf7f6a3c70587d"

        # Euler attacker in Curve window: MUST BE 0
        assert registry.is_malicious_in_window(euler_attacker, 17806770, 17851010) == 0

        # Curve attacker in Euler window: MUST BE 0
        assert registry.is_malicious_in_window(curve_attacker, 16817990, 16818110) == 0

    def test_benign_address_invariance(self):
        """Arbitrary benign addresses must never be labeled malicious regardless of block window."""
        registry = IndependentGroundTruthRegistry()
        vitalik = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
        zero_addr = "0x0000000000000000000000000000000000000000"

        for blk_start in [1000, 16818000, 17810000, 20000000]:
            assert registry.is_malicious_in_window(vitalik, blk_start, blk_start + 100) == 0
            assert registry.is_malicious_in_window(zero_addr, blk_start, blk_start + 100) == 0


# =====================================================================
# Dimension 4: ONNX vs PyTorch 1,000 Random Vector Stress Test
# =====================================================================

class TestAdversarialONNXPyTorchEquivalence:
    """Stress tests numerical parity between PyTorch, pure-Python MLP, and ONNX Runtime."""

    def test_1000_vector_numerical_equivalence(self):
        """Feed 1,000 Gaussian random, uniform, and edge feature vectors into both PyTorch
        and ONNX inference engines. Assert max absolute difference <= 1e-5.
        """
        import torch
        import onnx
        from onnx.reference import ReferenceEvaluator
        import numpy as np

        engine = ForensicMLInferenceEngine()
        assert engine.onnx_evaluator is not None, "ONNX evaluator must be initialized"
        assert engine.torch_model is not None, "PyTorch model must be initialized"

        rng = random.Random(1337)
        np_rng = np.random.default_rng(1337)

        # 1. 700 standard Gaussian vectors
        gaussian_vecs = np_rng.normal(loc=0.0, scale=1.0, size=(700, 10)).tolist()

        # 2. 200 uniform vectors across wide range [-50, 50]
        uniform_vecs = np_rng.uniform(low=-50.0, high=50.0, size=(200, 10)).tolist()

        # 3. 100 extreme boundary vectors (zeros, ones, large outliers, near-zero)
        boundary_vecs = [
            [0.0] * 10,
            [1.0] * 10,
            [-1.0] * 10,
            [100.0] * 10,
            [-100.0] * 10,
            [1e-6] * 10,
            [-1e-6] * 10,
        ]
        while len(boundary_vecs) < 100:
            vec = [rng.choice([0.0, 1.0, -1.0, 10.0, -10.0, 50.0, -50.0]) for _ in range(10)]
            boundary_vecs.append(vec)

        all_vectors = gaussian_vecs + uniform_vecs + boundary_vecs
        assert len(all_vectors) == 1000

        max_err_torch_onnx = 0.0
        max_err_py_onnx = 0.0
        max_err_torch_py = 0.0

        for i, vec in enumerate(all_vectors):
            rec_py = engine.predict(vec, backend="python", verify_tolerance=False)
            rec_torch = engine.predict(vec, backend="pytorch", verify_tolerance=False)
            rec_onnx = engine.predict(vec, backend="onnx", verify_tolerance=False)

            score_py = rec_py.prediction_score
            score_torch = rec_torch.prediction_score
            score_onnx = rec_onnx.prediction_score

            err_to = abs(score_torch - score_onnx)
            err_po = abs(score_py - score_onnx)
            err_tp = abs(score_torch - score_py)

            if err_to > max_err_torch_onnx:
                max_err_torch_onnx = err_to
            if err_po > max_err_py_onnx:
                max_err_py_onnx = err_po
            if err_tp > max_err_torch_py:
                max_err_torch_py = err_tp

            # Invariant check per vector
            assert err_to <= 1e-5, f"Vector {i}: PyTorch vs ONNX diff {err_to} > 1e-5"
            assert err_po <= 1e-5, f"Vector {i}: Python vs ONNX diff {err_po} > 1e-5"
            assert err_tp <= 1e-5, f"Vector {i}: PyTorch vs Python diff {err_tp} > 1e-5"

        print(f"\n[1000 Vectors] Max Torch-ONNX err: {max_err_torch_onnx:.2e}, "
              f"Max Py-ONNX err: {max_err_py_onnx:.2e}, Max Torch-Py err: {max_err_torch_py:.2e}")
        assert max_err_torch_onnx <= 1e-5
        assert max_err_py_onnx <= 1e-5
        assert max_err_torch_py <= 1e-5

    def test_verify_pytorch_onnx_equivalence_utility(self):
        """Test the registry's built-in equivalence verification utility."""
        engine = ForensicMLInferenceEngine()
        onnx_file = ROOT_DIR / "models" / "anomaly_detector_v1.onnx"
        test_samples = [[float(i + j * 0.1) for i in range(10)] for j in range(50)]

        is_equiv, max_err = verify_pytorch_onnx_equivalence(
            model=engine.torch_model,
            onnx_path=onnx_file,
            test_vectors=test_samples,
            float_tolerance=1e-5,
        )
        assert is_equiv is True
        assert max_err <= 1e-5


# =====================================================================
# Dimension 5: MITRE ATT&CK Grounded Mapping & Fail-Safe Abstain
# =====================================================================

class TestAdversarialMitreGroundedMapping:
    """Stress tests MITRE ATT&CK mapping grounding and fail-safe abstain mechanism."""

    def test_strict_evidence_rejection_without_abstain(self):
        """When fallback_to_abstain=False and strict_evidence=True, missing evidence
        must raise UnsubstantiatedMappingError.
        """
        engine = MitreMappingEngine(strict_evidence=True, fallback_to_abstain=False)
        features = {"max_single_out_ratio": 0.95, "volume_out_normalized": 50000.0}

        # Candidate mapping matches T1566.002, but evidence_refs is empty
        with pytest.raises(UnsubstantiatedMappingError):
            engine.map_anomaly(
                features=features,
                anomaly_score=0.90,
                rule_alerts=[],
                evidence_refs=[],
            )

    def test_fail_safe_abstain_returns_not_mapped(self):
        """With fallback_to_abstain=True, events lacking evidence or normal events
        must map to 'NOT_MAPPED' under tactic 'TA0043'.
        """
        engine = MitreMappingEngine(strict_evidence=True, fallback_to_abstain=True)

        # 1. Normal benign behavior WITH evidence ref -> ABSTAIN_NORMAL_BEHAVIOR
        res_benign = engine.map_anomaly(
            features={"max_single_out_ratio": 0.05},
            anomaly_score=0.10,
            rule_alerts=[],
            evidence_refs=["tx:0x1111111111111111111111111111111111111111111111111111111111111111"],
        )
        assert len(res_benign) == 1
        assert res_benign[0]["technique_id"] == "NOT_MAPPED"
        assert res_benign[0]["tactic_id"] == "TA0000"
        assert res_benign[0]["mapping_rule"] == "ABSTAIN_NORMAL_BEHAVIOR"

        # 2. Normal benign behavior WITHOUT evidence ref -> ABSTAIN_INSUFFICIENT_EVIDENCE
        res_no_evidence = engine.map_anomaly(
            features={"max_single_out_ratio": 0.05},
            anomaly_score=0.10,
            rule_alerts=[],
            evidence_refs=[],
        )
        assert len(res_no_evidence) == 1
        assert res_no_evidence[0]["technique_id"] == "NOT_MAPPED"
        assert res_no_evidence[0]["tactic_id"] == "TA0000"
        assert res_no_evidence[0]["mapping_rule"] == "ABSTAIN_INSUFFICIENT_EVIDENCE"


# =====================================================================
# Dimension 6: Adversarial XAI Axiom Stress & Model Diagnostics
# =====================================================================

class TestAdversarialXAIAndModelDiagnostics:
    """Stress tests XAI explanation axioms, degenerate fallbacks, and neuron health."""

    def test_xai_degenerate_input_fallback(self):
        """Pass degenerate vectors (NaN, Inf) and verify fail-safe NOT_EXPLAINABLE."""
        from forensics.ml.model import load_default_model
        model = load_default_model()
        explainer = ExactShapleyExplainer(model_predict_fn=model.forward_single)

        # 1. NaN input
        nan_vec = [float("nan")] * 10
        exp_nan = explainer.explain(nan_vec)
        assert exp_nan.status == "NOT_EXPLAINABLE"
        assert exp_nan.is_explainable is False
        assert "NaN or Infinite" in exp_nan.abstain_reason

        # 2. Infinite input
        inf_vec = [1.0, float("inf")] + [0.0] * 8
        exp_inf = explainer.explain(inf_vec)
        assert exp_inf.status == "NOT_EXPLAINABLE"
        assert exp_inf.is_explainable is False
        assert "NaN or Infinite" in exp_inf.abstain_reason

    def test_xai_quantitative_fidelity_and_stability_bounds(self):
        """Verify local linear surrogate fidelity (R^2 >= 0.80, L_local <= 0.05)
        and attribution stability (cosine sim >= 0.85).
        """
        from forensics.ml.model import load_default_model
        from forensics.ml.xai import compute_local_fidelity, compute_local_stability
        model = load_default_model()
        x_sample = [0.5, 1.2, 0.1, 0.0, 2.5, 0.8, 1.0, 0.3, 0.0, 0.2]

        explainer = ExactShapleyExplainer(model_predict_fn=model.forward_single)
        exp = explainer.explain(x_sample, evaluate_metrics=True)
        assert exp.status == "EXPLAINABLE"
        assert exp.is_explainable is True

        # Check fidelity and stability metrics
        assert exp.fidelity_r2 >= 0.80, f"Local fidelity R^2 {exp.fidelity_r2} < 0.80"
        assert exp.reconstruction_error <= 0.05, f"Reconstruction error {exp.reconstruction_error} > 0.05"
        assert exp.stability_score >= 0.85, f"Attribution stability {exp.stability_score} < 0.85"

    def test_active_neurons_under_gaussian_distribution(self):
        """Verify active neuron ratio >= 10% on random Gaussian samples (prevent dead ReLU)."""
        import numpy as np
        model = CompactAnomalyMLP(init_method="he", seed=42)
        rng = np.random.default_rng(42)
        X_samples = rng.normal(loc=0.0, scale=1.0, size=(100, 10)).tolist()
        active_info = check_active_neurons(model, X_samples)
        assert active_info["is_healthy"] is True
        assert active_info["layer1_active_ratio"] >= 0.10
        assert active_info["layer2_active_ratio"] >= 0.10


# =====================================================================
# Dimension 7: Read-Only DB Isolation & Zero Lock Files
# =====================================================================

class TestReadOnlyDBIsolation:
    """Verifies that feature extraction operates strictly read-only without lock files."""

    def test_extract_address_features_creates_no_lock_files(self):
        """Confirm that reading real_p4.db does not spawn -wal or -shm lock files."""
        db_path = ROOT_DIR / "data" / "real_p4.db"
        wal_path = ROOT_DIR / "data" / "real_p4.db-wal"
        shm_path = ROOT_DIR / "data" / "real_p4.db-shm"

        res = extract_address_features(db_path)
        assert len(res.features) > 0

        # Invariant: zero lock files created
        assert not wal_path.exists(), f"Found leaked WAL file: {wal_path}"
        assert not shm_path.exists(), f"Found leaked SHM file: {shm_path}"


# =====================================================================
# Dimension 8: Canonical Database Invariance Assertion
# =====================================================================

class TestCanonicalDatabaseInvariance:
    """Verifies that none of the stress tests modified canonical databases."""

    @pytest.mark.parametrize("db_name, expected_hash", CANONICAL_HASHES.items())
    def test_database_hash_invariant(self, db_name: str, expected_hash: str):
        if db_name == ".env":
            target_path = ROOT_DIR / ".env"
        else:
            target_path = ROOT_DIR / "data" / db_name

        assert target_path.is_file(), f"Database file {target_path} does not exist"
        current_hash = _compute_file_sha256(target_path)
        allowed = {h.lower() for h in accepted_env_sha256(ROOT_DIR)} if db_name == ".env" else {expected_hash}
        assert current_hash in allowed, (
            f"Bitwise integrity violation in {db_name}! "
            f"Expected {expected_hash}, got {current_hash}"
        )
