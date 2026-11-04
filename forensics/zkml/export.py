"""ONNX Model Export, Sanitization, and Validation Pipeline for ZKML (P9).

Responsibilities:
1. Export CompactAnomalyMLP / PyTorch models to static ONNX format (opset 17).
2. Enforce static tensor dimensions [1, 10] -> [1, 1] without dynamic axes.
3. Perform shape inference and structural ONNX validation.
4. Calculate and record cryptographic SHA-256 digests.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Sequence

import onnx
from onnx import helper, shape_inference, TensorProto

from forensics.ml.model import CompactAnomalyMLP


class ModelExportError(Exception):
    """Raised when ONNX export, sanitization, or validation fails."""
    pass


def export_model_to_zkml_onnx(
    model: CompactAnomalyMLP | Any,
    output_path: Path | str,
    input_shape: tuple[int, ...] = (1, 10),
    opset_version: int = 17,
) -> Path:
    """Exports CompactAnomalyMLP to a static ONNX file suitable for EZKL compilation.

    Guarantees:
    - Input shape is strictly fixed to input_shape (default [1, 10]).
    - Output shape is strictly fixed to [1, 1].
    - Graph uses canonical Gemm, Relu, Sigmoid nodes.
    - Verified via onnx.checker and shape_inference.
    """
    out_p = Path(output_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)

    if not isinstance(model, CompactAnomalyMLP):
        raise ModelExportError(f"Expected CompactAnomalyMLP instance, got {type(model).__name__}")

    # Flatten weights and biases
    w1_flat = [float(v) for row in model.w1 for v in row]
    b1_flat = [float(v) for v in model.b1]
    w2_flat = [float(v) for row in model.w2 for v in row]
    b2_flat = [float(v) for v in model.b2]
    w3_flat = [float(v) for row in model.w3 for v in row]
    b3_flat = [float(v) for v in model.b3]

    t_w1 = helper.make_tensor("w1", TensorProto.FLOAT, [model.hidden1, model.input_dim], w1_flat)
    t_b1 = helper.make_tensor("b1", TensorProto.FLOAT, [model.hidden1], b1_flat)
    t_w2 = helper.make_tensor("w2", TensorProto.FLOAT, [model.hidden2, model.hidden1], w2_flat)
    t_b2 = helper.make_tensor("b2", TensorProto.FLOAT, [model.hidden2], b2_flat)
    t_w3 = helper.make_tensor("w3", TensorProto.FLOAT, [model.output_dim, model.hidden2], w3_flat)
    t_b3 = helper.make_tensor("b3", TensorProto.FLOAT, [model.output_dim], b3_flat)

    # Computational Nodes (Gemm with transB=1 matches PyTorch Linear layer weight layout [out_features, in_features])
    n_gemm1 = helper.make_node("Gemm", ["input", "w1", "b1"], ["gemm1_out"], transB=1, name="Gemm_1")
    n_relu1 = helper.make_node("Relu", ["gemm1_out"], ["relu1_out"], name="Relu_1")
    n_gemm2 = helper.make_node("Gemm", ["relu1_out", "w2", "b2"], ["gemm2_out"], transB=1, name="Gemm_2")
    n_relu2 = helper.make_node("Relu", ["gemm2_out"], ["relu2_out"], name="Relu_2")
    n_gemm3 = helper.make_node("Gemm", ["relu2_out", "w3", "b3"], ["gemm3_out"], transB=1, name="Gemm_3")
    n_sig3 = helper.make_node("Sigmoid", ["gemm3_out"], ["output"], name="Sigmoid_3")

    # Inputs/Outputs ValueInfo with static shapes
    inp_info = helper.make_tensor_value_info("input", TensorProto.FLOAT, list(input_shape))
    out_info = helper.make_tensor_value_info("output", TensorProto.FLOAT, [input_shape[0], model.output_dim])

    graph = helper.make_graph(
        nodes=[n_gemm1, n_relu1, n_gemm2, n_relu2, n_gemm3, n_sig3],
        name="CompactAnomalyMLP",
        inputs=[inp_info],
        outputs=[out_info],
        initializer=[t_w1, t_b1, t_w2, t_b2, t_w3, t_b3],
    )

    onnx_model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", opset_version)])
    onnx_model = shape_inference.infer_shapes(onnx_model)
    onnx.checker.check_model(onnx_model)

    onnx.save(onnx_model, str(out_p))
    return out_p


def sanitize_onnx_for_zkml(
    input_onnx_path: Path | str,
    output_onnx_path: Path | str | None = None,
) -> Path:
    """Sanitizes an ONNX model ensuring strictly static shapes and opset conformance."""
    inp_p = Path(input_onnx_path)
    if not inp_p.is_file():
        raise ModelExportError(f"Input ONNX file not found: {inp_p}")

    out_p = Path(output_onnx_path) if output_onnx_path else inp_p
    out_p.parent.mkdir(parents=True, exist_ok=True)

    try:
        model = onnx.load(str(inp_p))
    except Exception as e:
        raise ModelExportError(f"Failed to load ONNX model: {e}") from e

    # Verify input shapes are concrete positive integers
    for inp in model.graph.input:
        shape = [d.dim_value for d in inp.type.tensor_type.shape.dim]
        if any(s <= 0 for s in shape):
            raise ModelExportError(f"Dynamic or invalid dimension found in input {inp.name}: {shape}")

    # Verify output shapes are concrete positive integers
    for out in model.graph.output:
        shape = [d.dim_value for d in out.type.tensor_type.shape.dim]
        if any(s <= 0 for s in shape):
            raise ModelExportError(f"Dynamic or invalid dimension found in output {out.name}: {shape}")

    # Shape inference & validation
    inferred = shape_inference.infer_shapes(model)
    onnx.checker.check_model(inferred)

    onnx.save(inferred, str(out_p))
    return out_p


def verify_zkml_onnx_compatibility(onnx_path: Path | str) -> tuple[bool, list[str]]:
    """Checks whether an ONNX model satisfies all EZKL circuit constraints."""
    p = Path(onnx_path)
    if not p.is_file():
        return False, [f"File not found: {p}"]

    issues: list[str] = []
    try:
        model = onnx.load(str(p))
        onnx.checker.check_model(model)
    except Exception as e:
        return False, [f"ONNX check failed: {e}"]

    allowed_ops = {"Gemm", "MatMul", "Add", "Relu", "Sigmoid", "Identity", "Constant"}
    for node in model.graph.node:
        if node.op_type not in allowed_ops:
            issues.append(f"Unsupported ZKML op: {node.op_type} ({node.name})")

    for inp in model.graph.input:
        for d in inp.type.tensor_type.shape.dim:
            if not d.dim_value or d.dim_value <= 0:
                issues.append(f"Non-static input dimension in {inp.name}")

    for out in model.graph.output:
        for d in out.type.tensor_type.shape.dim:
            if not d.dim_value or d.dim_value <= 0:
                issues.append(f"Non-static output dimension in {out.name}")

    return len(issues) == 0, issues


def get_model_architecture_summary(onnx_path: Path | str) -> dict[str, Any]:
    """Returns metadata summary including parameters, ops, and SHA-256."""
    p = Path(onnx_path)
    if not p.is_file():
        raise ModelExportError(f"Model file not found: {p}")

    model = onnx.load(str(p))
    sha256_hash = hashlib.sha256(p.read_bytes()).hexdigest()

    total_params = 0
    for init in model.graph.initializer:
        dims = list(init.dims)
        prod = 1
        for d in dims:
            prod *= d
        total_params += prod

    return {
        "graph_name": model.graph.name,
        "opset_version": model.opset_import[0].version if model.opset_import else 0,
        "node_count": len(model.graph.node),
        "total_parameters": total_params,
        "input_shape": [d.dim_value for d in model.graph.input[0].type.tensor_type.shape.dim],
        "output_shape": [d.dim_value for d in model.graph.output[0].type.tensor_type.shape.dim],
        "sha256": sha256_hash,
    }
