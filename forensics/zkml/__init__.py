"""Zero-Knowledge Machine Learning (ZKML) Verifiable Inference Module (Phase 4 / P9).

Provides verifiable inference using EZKL and Halo2 zero-knowledge proofs over
compact ONNX models (P8 Anomaly Detector).
"""
import os
import sys

# Windows OS Environment Guard for EZKL PyO3 bindings:
# EZKL requires HOME to be set for cache/config resolution.
if "HOME" not in os.environ and "USERPROFILE" in os.environ:
    os.environ["HOME"] = os.environ["USERPROFILE"]

from forensics.zkml.export import (
    ModelExportError,
    export_model_to_zkml_onnx,
    get_model_architecture_summary,
    sanitize_onnx_for_zkml,
    verify_zkml_onnx_compatibility,
)
from forensics.zkml.circuit import (
    CircuitConfig,
    CircuitError,
    calibrate_circuit_settings,
    compile_circuit,
    compute_input_commitment,
    dequantize_score,
    generate_circuit_settings,
    generate_witness,
    quantize_feature_vector,
    setup_circuit_srs,
    setup_keys,
)
from forensics.zkml.prover import ProofResult, ZKMLProofResult, ZKMLProver
from forensics.zkml.verifier import ZKMLVerifier, verify_proof

__all__ = [
    "ModelExportError",
    "export_model_to_zkml_onnx",
    "sanitize_onnx_for_zkml",
    "verify_zkml_onnx_compatibility",
    "get_model_architecture_summary",
    "CircuitConfig",
    "CircuitError",
    "quantize_feature_vector",
    "dequantize_score",
    "compute_input_commitment",
    "generate_circuit_settings",
    "calibrate_circuit_settings",
    "compile_circuit",
    "setup_circuit_srs",
    "setup_keys",
    "generate_witness",
    "ProofResult",
    "ZKMLProofResult",
    "ZKMLProver",
    "ZKMLVerifier",
    "verify_proof",
]
