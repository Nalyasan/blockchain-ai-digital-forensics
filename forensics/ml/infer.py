"""Unified Machine Learning Inference Engine for Blockchain Forensics (P8).

Supports PyTorch, ONNX, and Pure-Python backends with:
- Bitwise / float tolerance verification (<= 1e-5).
- Immutable cryptographic inference records (AGENT.md §6.1).
- Automatic backend fallback when optional libraries are unavailable.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Sequence

from forensics.ml.model import CompactAnomalyMLP, load_default_model
from forensics.ml.registry import compute_file_sha256, verify_model_integrity

try:
    import torch
    from forensics.ml.model import PyTorchAnomalyMLP
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

try:
    import onnx
    from onnx.reference import ReferenceEvaluator
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False


@dataclass(frozen=True)
class InferenceRecord:
    """Immutable forensic inference record complying with AGENT.md §6.1."""
    inference_id: str
    model_id: str
    model_sha256: str
    feature_schema_version: str
    input_evidence_refs: list[str]
    input_digest: str
    prediction_score: float
    threshold: float
    is_anomalous: bool
    inference_time_ms: float
    backend_used: str
    float_tolerance_verified: bool
    source_is_synthetic: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ForensicMLInferenceEngine:
    """Unified inference engine supporting PyTorch, ONNX, and Pure-Python."""

    def __init__(
        self,
        models_dir: Path | str | None = None,
        model_id: str = "anomaly_detector_v1",
        default_threshold: float = 0.65,
    ):
        self.models_dir = Path(models_dir or "D:/Projest/Blockchain/models")
        self.model_id = model_id
        self.threshold = default_threshold

        # Load pure-python model
        self.py_model = load_default_model(self.models_dir)
        self.onnx_path = self.models_dir / f"{model_id}.onnx"
        self.model_sha256 = self.py_model.model_sha256 or (
            compute_file_sha256(self.onnx_path) if self.onnx_path.is_file() else ""
        )

        # Initialize ONNX Reference Evaluator if available
        self.onnx_evaluator: Any | None = None
        if HAS_ONNX and self.onnx_path.is_file():
            try:
                onnx_proto = onnx.load(str(self.onnx_path))
                self.onnx_evaluator = ReferenceEvaluator(onnx_proto)
            except Exception:
                self.onnx_evaluator = None

        # Initialize PyTorch Model if available
        self.torch_model: Any | None = None
        if HAS_TORCH:
            try:
                self.torch_model = PyTorchAnomalyMLP()
                self.torch_model.load_from_compact_mlp(self.py_model)
                self.torch_model.eval()
            except Exception:
                self.torch_model = None

    def predict(
        self,
        features: Sequence[float],
        backend: str = "auto",
        evidence_refs: Sequence[str] | None = None,
        verify_tolerance: bool = True,
    ) -> InferenceRecord:
        """Runs inference and generates an immutable InferenceRecord."""
        x_vec = [float(v) for v in features]
        if len(x_vec) != 10:
            raise ValueError(f"Expected 10-dimensional feature vector, got {len(x_vec)}")

        t0 = time.perf_counter()
        tolerance_verified = True
        backend_used = backend

        # Compute Python baseline score
        py_score = self.py_model.forward_single(x_vec)
        selected_score = py_score

        # If PyTorch requested or auto
        if (backend in ("pytorch", "auto")) and self.torch_model is not None:
            t_input = torch.tensor([x_vec], dtype=torch.float32)
            with torch.no_grad():
                torch_score = float(self.torch_model(t_input).item())
            if verify_tolerance and abs(torch_score - py_score) > 1e-5:
                tolerance_verified = False
            selected_score = torch_score
            backend_used = "pytorch"

        # If ONNX requested
        elif backend == "onnx" and self.onnx_evaluator is not None:
            import numpy as np
            onnx_input = np.array([x_vec], dtype=np.float32)
            onnx_score = float(self.onnx_evaluator.run(None, {"input": onnx_input})[0][0][0])
            if verify_tolerance and abs(onnx_score - py_score) > 1e-5:
                tolerance_verified = False
            selected_score = onnx_score
            backend_used = "onnx"

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Input SHA-256 digest
        input_bytes = json.dumps([round(v, 8) for v in x_vec]).encode("utf-8")
        input_digest = hashlib.sha256(input_bytes).hexdigest()

        # Generate unique inference record id
        record_id = hashlib.sha256(
            f"{self.model_sha256}:{input_digest}:{time.time_ns()}".encode("utf-8")
        ).hexdigest()[:32]

        return InferenceRecord(
            inference_id=f"inf_{record_id}",
            model_id=self.model_id,
            model_sha256=self.model_sha256,
            feature_schema_version="1.0.0",
            input_evidence_refs=list(evidence_refs or []),
            input_digest=input_digest,
            prediction_score=round(selected_score, 6),
            threshold=self.threshold,
            is_anomalous=selected_score >= self.threshold,
            inference_time_ms=round(elapsed_ms, 3),
            backend_used=backend_used,
            float_tolerance_verified=tolerance_verified,
        )
