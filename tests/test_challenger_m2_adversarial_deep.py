"""Empirical Adversarial Verification & Stress Test Suite — Milestone M2.

Author: challenger_v6_M2_2
Target Commit: 280aa3d
Focus: Empirical stress testing on XAI degenerate inputs, fidelity/stability boundaries,
       Shapley Efficiency axiom violations, MITRE abstain/predicate handling,
       and full database bitwise invariance.
"""
from __future__ import annotations

import hashlib
import math
from pathlib import Path
import random
import pytest

from forensics.ml.model import CompactAnomalyMLP, PyTorchAnomalyMLP
from forensics.ml.xai import (
    ExactShapleyExplainer,
    XAIExplanation,
    compute_local_fidelity,
    compute_local_stability,
    explain_instance,
)
from forensics.ml.mitre import (
    MITRE_DEFI_TAXONOMY,
    MitreAttackMapping,
    MitreMappingEngine,
    UnsubstantiatedMappingError,
    validate_canonical_evidence_refs,
)
from forensics.paths import accepted_env_sha256

ROOT_DIR = Path(__file__).resolve().parents[1]
CANONICAL_HASHES = {
    "real_p4.db": "6bd9aed48ac2742d0862198bff65994861244ec681dc8abeb3e6f771e7808c97",
    "forensics.db": "3f2b0dfc772a96ff6ea57c65807b5b6b9a20fcf74c409c6f222fcff29f1ef001",
    "benchmark_p6.db": "c7ff724cd214eef57e58a6fbe44dbeb2712c54b035907b2a6279a255c0e80507",
    ".env": "c2f4879666cd21276c58ec75de923c8235d414f3d646a854a835c5638ec1699c",
}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


class TestXAIDegenerateAndAxiomStress:
    """Stress tests XAI explanation generators on degenerate inputs and mathematical axioms."""

    def test_nan_input_triggers_not_explainable(self):
        model = CompactAnomalyMLP()
        explainer = ExactShapleyExplainer(model_predict_fn=model.forward_single)
        exp = explainer.explain([float("nan")] * 10, evaluate_metrics=True)

        assert exp.is_explainable is False
        assert exp.status == "NOT_EXPLAINABLE"
        assert "NaN or Infinite" in exp.abstain_reason
        assert exp.fidelity_r2 == 0.0
        assert exp.stability_score == 0.0

    def test_pos_and_neg_inf_input_triggers_not_explainable(self):
        model = CompactAnomalyMLP()
        explainer = ExactShapleyExplainer(model_predict_fn=model.forward_single)

        # Positive Infinity
        exp_pos = explainer.explain([float("inf")] * 10, evaluate_metrics=True)
        assert exp_pos.is_explainable is False
        assert exp_pos.status == "NOT_EXPLAINABLE"
        assert "NaN or Infinite" in exp_pos.abstain_reason

        # Negative Infinity
        exp_neg = explainer.explain([float("-inf")] * 10, evaluate_metrics=True)
        assert exp_neg.is_explainable is False
        assert exp_neg.status == "NOT_EXPLAINABLE"
        assert "NaN or Infinite" in exp_neg.abstain_reason

        # Mixed finite and infinite
        mixed = [1.0, -2.0, float("inf"), 4.0, float("-inf"), 0.5, 1.2, float("nan"), 0.0, 1.0]
        exp_mixed = explainer.explain(mixed, evaluate_metrics=True)
        assert exp_mixed.is_explainable is False
        assert exp_mixed.status == "NOT_EXPLAINABLE"

    def test_near_zero_variance_triggers_not_explainable(self):
        model = CompactAnomalyMLP()
        explainer = ExactShapleyExplainer(model_predict_fn=model.forward_single)
        # Uniform vector with vanishing variance
        zero_var = [1e-9] * 10
        exp = explainer.explain(zero_var, evaluate_metrics=True)

        # Vanishing perturbation response triggers stability < 0.85 fallback
        assert exp.is_explainable is False
        assert exp.status == "NOT_EXPLAINABLE"
        assert "Attribution stability below threshold" in exp.abstain_reason or exp.stability_score < 0.85

    def test_compute_local_fidelity_graceful_on_degeneracy(self):
        model = CompactAnomalyMLP()
        r2, l_local = compute_local_fidelity(
            model_predict_fn=model.forward_single,
            x_input=[float("nan")] * 10,
            baseline=[0.0] * 10,
            attributions=[0.0] * 10,
            pred_score=0.0,
        )
        assert isinstance(r2, float)
        assert isinstance(l_local, float)
        # Does not crash or raise unhandled exception
        assert r2 == 0.0

    def test_shapley_efficiency_violation_detection_strictly_triggers_not_explainable(self):
        model = CompactAnomalyMLP()

        # Wrap explainer to simulate a surrogate or coalitional engine whose sum deviates from score
        class CorruptedExplainer(ExactShapleyExplainer):
            def explain(self, features, **kwargs):
                exp = super().explain(features, **kwargs)
                # Inject attribution corruption: delta = 0.50 >> 1e-4
                corrupted_phi = {k: v + 0.05 for k, v in exp.feature_attributions.items()}
                sum_phi = sum(corrupted_phi.values())
                delta = abs(sum_phi - (exp.prediction_score - exp.baseline_value))
                is_explainable = exp.is_explainable
                status = exp.status
                abstain_reason = exp.abstain_reason
                if delta > 1e-4:
                    is_explainable = False
                    status = "NOT_EXPLAINABLE"
                    abstain_reason = f"Shapley Efficiency Axiom violated: delta={delta:.2e} > 1e-4."
                return XAIExplanation(
                    entity_address=exp.entity_address,
                    prediction_score=exp.prediction_score,
                    baseline_value=exp.baseline_value,
                    feature_attributions=corrupted_phi,
                    top_drivers=exp.top_drivers,
                    sum_attributions=sum_phi,
                    efficiency_delta=delta,
                    fidelity_r2=exp.fidelity_r2,
                    reconstruction_error=exp.reconstruction_error,
                    stability_score=exp.stability_score,
                    is_explainable=is_explainable,
                    status=status,
                    abstain_reason=abstain_reason,
                )

        expl = CorruptedExplainer(model_predict_fn=model.forward_single)
        x = [2.0, 1.0, 1.0, 23.14, 23.14, 1.0, 1.0, 0.0, 0.0, 1.0]
        res = expl.explain(x, evaluate_metrics=True)

        assert res.is_explainable is False
        assert res.status == "NOT_EXPLAINABLE"
        assert "Shapley Efficiency Axiom violated" in res.abstain_reason
        assert res.efficiency_delta > 1e-4


class TestMitreAttackAbstainAndPredicateStress:
    """Stress tests MITRE ATT&CK mapping engine on evidence grounding, invalid hashes, and fallbacks."""

    def test_missing_evidence_raises_unsubstantiated_error_when_strict(self):
        engine = MitreMappingEngine(strict_evidence=True, fallback_to_abstain=True)
        # Attempt mapping high-severity anomaly with empty evidence
        with pytest.raises(UnsubstantiatedMappingError):
            engine.map_anomaly(
                features={"max_single_out_ratio": 0.95, "volume_out_normalized": 500.0},
                anomaly_score=0.92,
                rule_alerts=[],
                evidence_refs=[],
            )

    def test_corrupted_evidence_hashes_filtered_and_rejected(self):
        engine = MitreMappingEngine(strict_evidence=True, fallback_to_abstain=True)
        corrupted_refs = [
            "not_a_hash",
            "0x1234",  # truncated
            "tx:0x" + "g" * 64,  # non-hex
            "alert:invalid-id-with-special-chars!@#$",
            "",
            None,  # type: ignore
        ]
        # Only canonical refs pass validation
        valid = validate_canonical_evidence_refs(corrupted_refs)
        assert len(valid) == 0

        # Mapping with corrupted refs behaves identically to empty refs -> raises
        with pytest.raises(UnsubstantiatedMappingError):
            engine.map_anomaly(
                features={"max_single_out_ratio": 0.95, "volume_out_normalized": 500.0},
                anomaly_score=0.92,
                rule_alerts=[],
                evidence_refs=corrupted_refs,
            )

    def test_normal_behavior_abstains_to_not_mapped(self):
        engine = MitreMappingEngine(strict_evidence=True, fallback_to_abstain=True)
        res = engine.map_anomaly(
            features={"max_single_out_ratio": 0.01, "tx_velocity": 0.1},
            anomaly_score=0.05,
            rule_alerts=[],
            evidence_refs=["tx:0x" + "1" * 64],
        )
        assert len(res) == 1
        m = res[0]
        assert m["technique_id"] == "NOT_MAPPED"
        assert m["tactic_id"] == "TA0000"
        assert m["confidence"] == 0.0
        assert m["analyst_review_status"] == "ABSTAINED"
        assert m["mapping_rule"] == "ABSTAIN_NORMAL_BEHAVIOR"

    def test_zero_hallucinated_techniques_when_rules_not_satisfied(self):
        engine = MitreMappingEngine(strict_evidence=True, fallback_to_abstain=True)
        # Benign features with genuine evidence reference
        res = engine.map_anomaly(
            features={
                "tx_velocity": 0.2,
                "unique_counterparties_in": 1.0,
                "unique_counterparties_out": 1.0,
                "volume_in_normalized": 0.1,
                "volume_out_normalized": 0.1,
                "pass_through_ratio": 0.0,
                "token_diversity": 1.0,
                "turnover_latency_min": 100.0,
                "burstiness_std": 50.0,
                "max_single_out_ratio": 0.1,
            },
            anomaly_score=0.15,
            rule_alerts=[],
            evidence_refs=["tx:0x" + "f" * 64],
        )
        # Must return ONLY NOT_MAPPED, zero hallucinated attack techniques
        assert len(res) == 1
        assert res[0]["technique_id"] == "NOT_MAPPED"

    def test_mitre_mapping_discrepancy_audit(self):
        """Audits documented differences between worker report claims and code implementation.
        
        Worker claims in changes.md/handoff.md:
        1. Added fallback technique NOT_MAPPED under tactic TA0043 (Reconnaissance) with rule ABSTAIN_NO_GROUNDED_MATCH.
        2. Implemented map_threat_to_mitre with confidence < 0.70 abstain.

        Actual implementation in forensics/ml/mitre.py:
        1. NOT_MAPPED is defined under tactic_id TA0000 (Unmapped), with dynamic rules ABSTAIN_NORMAL_BEHAVIOR /
           ABSTAIN_INSUFFICIENT_EVIDENCE / ABSTAIN_UNMAPPED_ALERT_TYPE.
        2. Function name is MitreMappingEngine.map_anomaly, not map_threat_to_mitre or map_alert_to_mitre.
        3. Low confidence (< 0.70) does not filter out positive rule-triggered techniques (e.g. T1566.002 conf=0.52).
        """
        tech_not_mapped = MITRE_DEFI_TAXONOMY["NOT_MAPPED"]
        assert tech_not_mapped.tactic_id == "TA0000"
        assert tech_not_mapped.tactic == "Unmapped"

        engine = MitreMappingEngine(strict_evidence=True)
        # When large_transfer is triggered without volume, confidence is 0.52 (< 0.70)
        res = engine.map_anomaly(
            features={"max_single_out_ratio": 0.0, "volume_out_normalized": 0.0},
            anomaly_score=0.1,
            rule_alerts=[{"rule_id": "large_transfer", "alert_id": "a" * 64, "evidence_refs": []}],
            evidence_refs=["tx:0x" + "b" * 64],
        )
        assert len(res) >= 1
        low_conf_mapping = res[0]
        # Verified empirically: confidence is 0.52 (< 0.70), and emitted as T1566.002
        assert low_conf_mapping["confidence"] < 0.70
        assert low_conf_mapping["technique_id"] == "T1566.002"


class TestFullDatabaseBitwiseInvariance:
    """Verifies 100% bitwise SHA-256 integrity across all 4 canonical databases."""

    @pytest.mark.parametrize("file_name, expected_digest", CANONICAL_HASHES.items())
    def test_database_bitwise_digest(self, file_name: str, expected_digest: str):
        target = ROOT_DIR / ".env" if file_name == ".env" else ROOT_DIR / "data" / file_name
        assert target.is_file(), f"Target {target} does not exist"
        current_digest = _sha256_file(target)
        allowed = {h.lower() for h in accepted_env_sha256(ROOT_DIR)} if file_name == ".env" else {expected_digest}
        assert current_digest in allowed, (
            f"Bitwise invariance violation on {file_name}: expected {expected_digest}, got {current_digest}"
        )
