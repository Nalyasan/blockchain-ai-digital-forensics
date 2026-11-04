"""Test Suite 2: P8 Quantitative XAI & Dual-Engine Corroboration.

Tests:
1. Exact Shapley Efficiency Axiom: sum(phi_i) == f(x) - E[f(x)].
2. Shapley Dummy Player, Symmetry, and Determinism axioms.
3. Top feature drivers ranking and formatting.
4. Dual-engine corroboration: 4-way classification matrix.
5. Probabilistic Noisy-OR confidence combination and uncorroborated discounting.
6. Semantic concordance matching between XAI drivers and triggered rules.
7. Real incident ground truth corroboration on Euler Finance and Curve alETH.
"""
from __future__ import annotations

import math
from pathlib import Path
import pytest

from forensics.paths import REAL_P4_DB
from forensics.rules.base import Alert
from forensics.ml.features import FEATURE_NAMES
from forensics.ml.model import CompactAnomalyMLP
from forensics.ml.xai import (
    ExactShapleyExplainer,
    XAIExplanation,
    explain_instance,
)
from forensics.ml.corroboration import (
    CorroboratedDetection,
    DualEngineCorroborator,
)


class TestExactShapleyExplainer:
    """Verifies axiomatic mathematical properties of ExactShapleyExplainer."""

    def test_efficiency_axiom_on_compact_mlp(self):
        """Verifies sum(phi_i) == f(x) - E[f(x)] within 1e-10 machine tolerance."""
        model = CompactAnomalyMLP()
        explainer = ExactShapleyExplainer(
            model_predict_fn=model.forward_single,
            baseline_vector=[0.0] * 10,
        )

        test_inputs = [
            [2.0, 1.0, 1.0, 23.14, 23.14, 1.0, 1.0, 0.0, 0.0, 1.0],  # Euler attacker profile
            [10.0, 5.0, 1.0, 15.0, 0.0, 0.0, 2.0, 0.0, 3.5, 0.0],
            [1.0, 0.0, 1.0, 0.0, 18.2, 10.0, 1.0, 0.0, 0.0, 1.0],
        ]

        for x in test_inputs:
            explanation = explainer.explain(x)
            assert explanation.efficiency_delta < 1e-8
            expected_diff = explanation.prediction_score - explanation.baseline_value
            assert abs(explanation.sum_attributions - expected_diff) < 1e-8

    def test_dummy_player_axiom(self):
        """Feature that has 0 effect on model output must receive exactly phi_i = 0.0."""
        # Function depends only on feature 0 and feature 1; feature 2..9 are dummies
        def dummy_model_fn(x: list[float]) -> float:
            return 1.0 / (1.0 + math.exp(-(0.5 * x[0] + 0.3 * x[1])))

        explainer = ExactShapleyExplainer(
            model_predict_fn=dummy_model_fn,
            baseline_vector=[0.0] * 10,
        )

        test_x = [2.0, 3.0, 99.0, 42.0, 13.0, 88.0, 77.0, 66.0, 55.0, 44.0]
        exp = explainer.explain(test_x)

        # Features 2 through 9 are dummy players
        for i in range(2, 10):
            feat_name = FEATURE_NAMES[i]
            assert abs(exp.feature_attributions[feat_name]) < 1e-12

    def test_symmetry_axiom(self):
        """Symmetric features with identical weights and inputs must receive identical Shapley values."""
        # Symmetric in feature 0 and feature 1
        def sym_model_fn(x: list[float]) -> float:
            return 1.0 / (1.0 + math.exp(-(x[0] + x[1])))

        explainer = ExactShapleyExplainer(
            model_predict_fn=sym_model_fn,
            baseline_vector=[0.0] * 10,
        )

        test_x = [2.5, 2.5, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        exp = explainer.explain(test_x)

        phi_0 = exp.feature_attributions[FEATURE_NAMES[0]]
        phi_1 = exp.feature_attributions[FEATURE_NAMES[1]]
        assert abs(phi_0 - phi_1) < 1e-12

    def test_determinism_and_top_drivers_ranking(self):
        model = CompactAnomalyMLP()
        explainer = ExactShapleyExplainer(
            model_predict_fn=model.forward_single,
            baseline_vector=[0.0] * 10,
        )

        test_x = [5.0, 2.0, 3.0, 20.0, 18.0, 0.9, 2.0, 1.0, 0.5, 1.0]
        exp1 = explainer.explain(test_x, top_k=3)
        exp2 = explainer.explain(test_x, top_k=3)

        # Bitwise identical
        assert exp1.prediction_score == exp2.prediction_score
        assert exp1.sum_attributions == exp2.sum_attributions
        assert exp1.top_drivers == exp2.top_drivers

        # Verify top drivers formatting
        assert len(exp1.top_drivers) <= 3
        for d in exp1.top_drivers:
            assert ":" in d
            assert "+" in d or "-" in d

    def test_zero_delta_on_baseline_input(self):
        model = CompactAnomalyMLP()
        baseline = [0.0] * 10
        explainer = ExactShapleyExplainer(
            model_predict_fn=model.forward_single,
            baseline_vector=baseline,
        )

        exp = explainer.explain(baseline)
        assert abs(exp.sum_attributions) < 1e-12
        for val in exp.feature_attributions.values():
            assert abs(val) < 1e-12
        assert exp.top_drivers == ["baseline_activity: +0.00"]


class TestDualEngineCorroboration:
    """Verifies cross-referencing ML scores with Rule Engine P4 alerts."""

    def _make_dummy_alert(self, rule_id: str, score: float = 1.0, tx_hash: str = "0x" + "a" * 64) -> Alert:
        return Alert(
            alert_id="f" * 64,
            rule_id=rule_id,
            rule_version="1.0.0",
            unit_type="address_window",
            unit_key="0x1111111111111111111111111111111111111111",
            asset_id="0x6b175474e89094c44da98b954eedeac495271d0f",
            severity="HIGH",
            score=score,
            reason=f"Detected anomaly by {rule_id}",
            evidence_refs=[{"tx_hash": tx_hash, "chain_id": 1, "block_number": 16817990}],
            window_start="2026-03-13T09:00:00Z",
            window_end="2026-03-13T09:30:00Z",
            created_at="2026-03-13T09:30:00Z",
        )

    def test_corroboration_classification_matrix(self):
        corroborator = DualEngineCorroborator(ml_anomaly_threshold=0.65)
        alert = self._make_dummy_alert("large_transfer")

        # 1. CORROBORATED (ML high, Rule fired)
        res1 = corroborator.corroborate("0x1111", ml_score=0.85, rule_alerts=[alert])
        assert res1.status == "CORROBORATED"
        assert res1.combined_score >= 0.85
        assert len(res1.supporting_tx_hashes) == 1

        # 2. ML_ONLY (ML high, Rule empty)
        res2 = corroborator.corroborate("0x1111", ml_score=0.80, rule_alerts=[])
        assert res2.status == "ML_ONLY"
        assert res2.combined_score == pytest.approx(0.80 * 0.85)

        # 3. RULE_ONLY (ML low, Rule fired)
        res3 = corroborator.corroborate("0x1111", ml_score=0.30, rule_alerts=[alert])
        assert res3.status == "RULE_ONLY"
        assert res3.combined_score == pytest.approx(1.0 * 0.90)

        # 4. NORMAL (ML low, Rule empty)
        res4 = corroborator.corroborate("0x1111", ml_score=0.20, rule_alerts=[])
        assert res4.status == "NORMAL"
        assert res4.combined_score == 0.20

    def test_noisy_or_confidence_math(self):
        corroborator = DualEngineCorroborator(ml_anomaly_threshold=0.65)
        alert = self._make_dummy_alert("rapid_pass_through", score=0.90)

        # Formula: 1 - (1 - 0.70)(1 - 0.90) = 1 - (0.30 * 0.10) = 1 - 0.03 = 0.97
        res = corroborator.corroborate("0x1111", ml_score=0.70, rule_alerts=[alert])
        assert res.status == "CORROBORATED"
        assert abs(res.combined_score - 0.97) < 1e-4
        assert res.combined_score >= max(0.70, 0.90)

    def test_semantic_concordance_matching(self):
        corroborator = DualEngineCorroborator(ml_anomaly_threshold=0.65)
        alert_rf = self._make_dummy_alert("high_frequency")
        drivers = ["high_tx_velocity: +0.45", "burstiness_spike: +0.20"]

        res = corroborator.corroborate("0x1111", ml_score=0.88, xai_top_drivers=drivers, rule_alerts=[alert_rf])
        assert res.status == "CORROBORATED"
        assert res.semantic_concordance is True
        assert "high_frequency" in res.concordant_rules

    def test_real_euler_incident_corroboration(self):
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not present at default path")

        corroborator = DualEngineCorroborator(db_path_or_conn=REAL_P4_DB, ml_anomaly_threshold=0.60)
        # Euler attacker frontrun entity in real_p4.db
        euler_attacker = "0xebc29199c817dc47ba12e3f86102564d640cbf99"
        alerts = corroborator.get_alerts_for_address(euler_attacker)
        assert len(alerts) > 0

        res = corroborator.corroborate(
            entity_address=euler_attacker,
            ml_score=0.92,
            xai_top_drivers=["abnormal_volume_out: +0.40", "concentrated_outflow: +0.30"],
        )
        assert res.status == "CORROBORATED"
        assert res.combined_score > 0.95
        assert len(res.supporting_tx_hashes) > 0
        corroborator.close()

    def test_real_curve_incident_corroboration(self):
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not present at default path")

        corroborator = DualEngineCorroborator(db_path_or_conn=REAL_P4_DB, ml_anomaly_threshold=0.60)
        # Curve exploit contract entity in real_p4.db
        curve_entity = "0xb657b895b265c38c53fff00166cf7f6a3c70587d"
        alerts = corroborator.get_alerts_for_address(curve_entity)
        assert len(alerts) > 0

        res = corroborator.corroborate(
            entity_address=curve_entity,
            ml_score=0.95,
            xai_top_drivers=["high_fan_out: +0.50"],
        )
        assert res.status == "CORROBORATED"
        assert len(res.supporting_tx_hashes) > 0
        corroborator.close()
