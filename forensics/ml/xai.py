"""Quantitative Explainable AI (XAI) Module for Blockchain Forensics (P8).

Provides exact Shapley value local feature attribution and deterministic
top explanatory driver extraction for the 10-feature anomaly detector.
Evaluates all 2^10 = 1024 feature coalitions in pure Python (~1.6ms), guaranteeing
the mathematical Efficiency Axiom: sum(phi_i) == f(x) - E[f(x)].
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Callable, Sequence

from forensics.ml.features import FEATURE_NAMES

CANONICAL_FEATURE_NAMES: list[str] = list(FEATURE_NAMES)

FEATURE_DRIVER_PREFIXES: dict[str, str] = {
    "tx_velocity": "high_tx_velocity",
    "unique_counterparties_in": "high_fan_in",
    "unique_counterparties_out": "high_fan_out",
    "volume_in_normalized": "abnormal_volume_in",
    "volume_out_normalized": "abnormal_volume_out",
    "pass_through_ratio": "abnormal_pass_through",
    "token_diversity": "high_token_diversity",
    "turnover_latency_min": "rapid_turnover",
    "burstiness_std": "burstiness_spike",
    "max_single_out_ratio": "concentrated_outflow",
}


@dataclass(frozen=True)
class XAIExplanation:
    """Structured XAI attribution output for a single entity evaluation."""
    entity_address: str
    prediction_score: float
    baseline_value: float  # E[f(x)]
    feature_attributions: dict[str, float]  # {feat_name: phi_i}
    top_drivers: list[str]  # e.g. ["high_tx_velocity: +0.38", "abnormal_pass_through: +0.29"]
    sum_attributions: float  # sum(phi_i)
    efficiency_delta: float  # abs(sum_attributions - (prediction_score - baseline_value))

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_address": self.entity_address,
            "prediction_score": round(self.prediction_score, 6),
            "baseline_value": round(self.baseline_value, 6),
            "feature_attributions": {k: round(v, 6) for k, v in self.feature_attributions.items()},
            "top_drivers": list(self.top_drivers),
            "sum_attributions": round(self.sum_attributions, 6),
            "efficiency_delta": float(f"{self.efficiency_delta:.2e}"),
        }


class ExactShapleyExplainer:
    """Exact combinatorial Shapley value computer for models with <= 12 features.

    Evaluates all 2^M coalitions to guarantee exact Efficiency, Symmetry,
    Dummy Player, and Additivity without sampling variance or random seeds.
    """

    def __init__(
        self,
        model_predict_fn: Callable[[Sequence[float]], float],
        baseline_vector: Sequence[float] | None = None,
        feature_names: Sequence[str] | None = None,
    ):
        """
        Args:
            model_predict_fn: Callable accepting 1D feature vector of length M and returning float score in [0, 1].
            baseline_vector: Reference baseline vector representing normal behavior. Defaults to all zeros.
            feature_names: Names for features. Defaults to CANONICAL_FEATURE_NAMES.
        """
        self.predict_fn = model_predict_fn
        self.feature_names = list(feature_names or CANONICAL_FEATURE_NAMES)
        self.num_features = len(self.feature_names)
        self.baseline = list(baseline_vector or [0.0] * self.num_features)

        if len(self.baseline) != self.num_features:
            raise ValueError(
                f"Baseline vector length ({len(self.baseline)}) must match feature count ({self.num_features})"
            )

        # Precompute factorial weights W(|S|) = (|S|! * (M - |S| - 1)!) / M!
        M = self.num_features
        facts = [math.factorial(i) for i in range(M + 1)]
        self._weights = [
            (facts[s] * facts[M - s - 1]) / facts[M]
            for s in range(M)
        ]

    def explain(
        self,
        features: Sequence[float] | dict[str, float],
        entity_address: str = "0x0000000000000000000000000000000000000000",
        top_k: int = 3,
    ) -> XAIExplanation:
        """Compute exact Shapley values for input features."""
        if isinstance(features, dict):
            x = [float(features.get(name, 0.0)) for name in self.feature_names]
        else:
            x = [float(v) for v in features]

        M = self.num_features
        b = self.baseline

        if len(x) != M:
            raise ValueError(f"Input features length ({len(x)}) must match expected ({M})")

        total_subsets = 1 << M
        # 1. Evaluate all 2^M subset coalitions
        v = [0.0] * total_subsets
        for mask in range(total_subsets):
            sub_vec = [x[j] if (mask & (1 << j)) else b[j] for j in range(M)]
            v[mask] = float(self.predict_fn(sub_vec))

        base_val = v[0]
        pred_val = v[total_subsets - 1]

        # 2. Accumulate marginal contributions for each feature i
        phi = [0.0] * M
        for i in range(M):
            bit_i = 1 << i
            val = 0.0
            for mask in range(total_subsets):
                if not (mask & bit_i):
                    s = bin(mask).count("1")
                    val += self._weights[s] * (v[mask | bit_i] - v[mask])
            phi[i] = val

        attributions = {self.feature_names[i]: phi[i] for i in range(M)}
        sum_phi = sum(phi)
        expected_diff = pred_val - base_val
        delta = abs(sum_phi - expected_diff)

        # 3. Deterministic Top Explanatory Drivers Extraction
        top_drivers = self._format_top_drivers(attributions, top_k=top_k)

        return XAIExplanation(
            entity_address=entity_address,
            prediction_score=pred_val,
            baseline_value=base_val,
            feature_attributions=attributions,
            top_drivers=top_drivers,
            sum_attributions=sum_phi,
            efficiency_delta=delta,
        )

    def _format_top_drivers(
        self,
        attributions: dict[str, float],
        top_k: int = 3,
    ) -> list[str]:
        """Rank and format top positive drivers deterministically."""
        # Sort by contribution descending, then by name ascending for determinism
        sorted_feats = sorted(
            attributions.items(),
            key=lambda item: (-item[1], item[0]),
        )
        drivers: list[str] = []
        for feat, val in sorted_feats[:top_k]:
            if val <= 0.0001:
                break
            prefix = FEATURE_DRIVER_PREFIXES.get(feat, feat)
            drivers.append(f"{prefix}: {val:+.2f}")

        if not drivers:
            drivers = ["baseline_activity: +0.00"]
        return drivers


def explain_instance(
    model: Any,
    features: Sequence[float] | dict[str, float],
    entity_address: str = "0x0000000000000000000000000000000000000000",
    baseline: Sequence[float] | None = None,
    top_k: int = 3,
) -> dict[str, Any]:
    """Helper function to run ExactShapleyExplainer on an instance."""
    predict_fn = getattr(model, "predict_score", None) or getattr(model, "forward_single", None)
    if predict_fn is None and callable(model):
        predict_fn = model
    if predict_fn is None:
        raise ValueError("Model must have predict_score, forward_single, or be callable.")

    explainer = ExactShapleyExplainer(
        model_predict_fn=predict_fn,
        baseline_vector=baseline,
        feature_names=CANONICAL_FEATURE_NAMES,
    )
    explanation = explainer.explain(features, entity_address=entity_address, top_k=top_k)
    return {
        "score": explanation.prediction_score,
        "baseline": explanation.baseline_value,
        "attributions": explanation.feature_attributions,
        "top_drivers": explanation.top_drivers,
        "efficiency_delta": explanation.efficiency_delta,
    }
