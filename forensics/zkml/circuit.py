"""Halo2 / EZKL Circuit Settings, Calibration, SRS, and Compilation (P9).

Responsibilities:
1. Generate CircuitConfig: scale factors, logrows, visibility, KZG commitment.
2. Manage circuit settings JSON generation and calibration with real feature data.
3. Structured Reference String (SRS) generation and local caching.
4. Halo2 circuit compilation and prover/verifier key setup.
5. Fixed-point quantization, dequantization, and input commitments.
6. Witness generation from real input feature vectors.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any, Sequence

# Windows Environment Guard for EZKL
if "HOME" not in os.environ and "USERPROFILE" in os.environ:
    os.environ["HOME"] = os.environ["USERPROFILE"]

import ezkl


class CircuitError(Exception):
    """Raised when circuit configuration, compilation, or key generation fails."""
    pass


@dataclass
class CircuitConfig:
    """Configuration parameters for Halo2 KZG arithmetic circuit."""
    input_scale: int = 7
    param_scale: int = 7
    logrows: int = 14  # 2^14 = 16,384 rows (optimal for 321-param MLP with lookups)
    lookup_range: tuple[float, float] = (-16.0, 16.0)
    num_inner_cols: int = 2
    scale_rebase_multiplier: int = 1
    input_visibility: str = "public"
    output_visibility: str = "public"
    param_visibility: str = "fixed"
    commitment_scheme: str = "KZG"


def quantize_feature_vector(features: Sequence[float], scale_bits: int = 7) -> list[int]:
    """Quantizes real feature values into signed integers with scale S = 2^scale_bits."""
    S = 2 ** scale_bits
    return [int(round(float(v) * S)) for v in features]


def dequantize_score(quantized_val: int, scale_bits: int = 7) -> float:
    """Dequantizes an integer score back to float in [0.0, 1.0]."""
    S = 2 ** scale_bits
    return float(quantized_val) / float(S)


def compute_input_commitment(features: Sequence[float], scale_bits: int = 7) -> str:
    """Computes deterministic SHA-256 commitment of the quantized input vector.

    Encodes each quantized integer as 8-byte little-endian signed integer.
    """
    q_vec = quantize_feature_vector(features, scale_bits=scale_bits)
    raw_bytes = b"".join(int(v).to_bytes(8, byteorder="little", signed=True) for v in q_vec)
    return hashlib.sha256(raw_bytes).hexdigest()


def generate_circuit_settings(
    onnx_path: Path | str,
    output_settings_path: Path | str,
    config: CircuitConfig | None = None,
) -> dict[str, Any]:
    """Generates canonical settings.json for EZKL circuit compilation."""
    cfg = config or CircuitConfig()
    onnx_p = Path(onnx_path)
    if not onnx_p.is_file():
        raise CircuitError(f"ONNX model file not found: {onnx_p}")

    out_p = Path(output_settings_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)

    py_run_args = ezkl.PyRunArgs()
    py_run_args.input_visibility = cfg.input_visibility.lower()
    py_run_args.output_visibility = cfg.output_visibility.lower()
    py_run_args.param_visibility = cfg.param_visibility.lower()
    if cfg.input_scale is not None:
        py_run_args.input_scale = cfg.input_scale
    if cfg.param_scale is not None:
        py_run_args.param_scale = cfg.param_scale
    if cfg.logrows is not None:
        py_run_args.logrows = cfg.logrows

    try:
        ezkl.gen_settings(model=str(onnx_p), output=str(out_p), py_run_args=py_run_args)
    except Exception as e:
        raise CircuitError(f"EZKL gen_settings failed: {e}") from e

    if not out_p.is_file():
        raise CircuitError(f"Settings file was not created: {out_p}")

    with open(out_p, "r", encoding="utf-8") as f:
        return json.load(f)


def calibrate_circuit_settings(
    input_path: Path | str,
    onnx_path: Path | str,
    settings_path: Path | str,
    target: str = "resources",
) -> bool:
    """Calibrates scale factors and logrows using empirical feature distribution."""
    inp_p = Path(input_path)
    onnx_p = Path(onnx_path)
    sett_p = Path(settings_path)

    if not inp_p.is_file():
        raise CircuitError(f"Calibration input file not found: {inp_p}")
    if not onnx_p.is_file():
        raise CircuitError(f"ONNX file not found: {onnx_p}")
    if not sett_p.is_file():
        raise CircuitError(f"Settings file not found: {sett_p}")

    try:
        res = ezkl.calibrate_settings(
            data=str(inp_p),
            model=str(onnx_p),
            settings=str(sett_p),
            target=target,
        )
        return bool(res)
    except Exception as e:
        raise CircuitError(f"EZKL calibrate_settings failed: {e}") from e


def compile_circuit(
    onnx_path: Path | str,
    compiled_path: Path | str,
    settings_path: Path | str,
) -> Path:
    """Compiles an ONNX model into a Halo2 arithmetic circuit binary."""
    onnx_p = Path(onnx_path)
    comp_p = Path(compiled_path)
    sett_p = Path(settings_path)

    if not onnx_p.is_file():
        raise CircuitError(f"ONNX model file not found: {onnx_p}")
    if not sett_p.is_file():
        raise CircuitError(f"Settings file not found: {sett_p}")

    comp_p.parent.mkdir(parents=True, exist_ok=True)

    try:
        ezkl.compile_circuit(
            str(onnx_p),
            str(comp_p),
            str(sett_p),
        )
    except Exception as e:
        raise CircuitError(f"EZKL compile_circuit failed: {e}") from e

    if not comp_p.is_file():
        raise CircuitError(f"Compiled circuit was not created: {comp_p}")

    return comp_p


def setup_circuit_srs(srs_path: Path | str, logrows: int = 14) -> Path:
    """Generates or retrieves a Structured Reference String (SRS) for BN254 KZG.

    Uses entirely local generation without requiring network download.
    """
    p = Path(srs_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    # Check if existing SRS file has sufficient size (SRS for logrows=k has 2^(k+1)*32+... bytes)
    min_bytes = (2 ** logrows) * 64
    if p.is_file() and p.stat().st_size >= min_bytes:
        return p

    try:
        ezkl.gen_srs(str(p), logrows)
    except Exception as e:
        raise CircuitError(f"EZKL gen_srs failed for logrows={logrows}: {e}") from e

    if not p.is_file() or p.stat().st_size == 0:
        raise CircuitError(f"SRS file was not created or is empty: {p}")

    return p


def setup_keys(
    compiled_path: Path | str,
    vk_path: Path | str,
    pk_path: Path | str,
    srs_path: Path | str,
) -> tuple[Path, Path]:
    """Generates the KZG proving key (pk) and verification key (vk)."""
    comp_p = Path(compiled_path)
    vk_p = Path(vk_path)
    pk_p = Path(pk_path)
    srs_p = Path(srs_path)

    if not comp_p.is_file():
        raise CircuitError(f"Compiled circuit not found: {comp_p}")
    if not srs_p.is_file():
        raise CircuitError(f"SRS file not found: {srs_p}")

    vk_p.parent.mkdir(parents=True, exist_ok=True)
    pk_p.parent.mkdir(parents=True, exist_ok=True)

    try:
        ezkl.setup(
            str(comp_p),
            str(vk_p),
            str(pk_p),
            str(srs_p),
        )
    except Exception as e:
        raise CircuitError(f"EZKL setup key generation failed: {e}") from e

    if not vk_p.is_file() or not pk_p.is_file():
        raise CircuitError("VK or PK was not created after setup")

    return vk_p, pk_p


def generate_witness(
    input_data: Sequence[float] | dict[str, Any] | Path | str,
    compiled_model_path: Path | str,
    output_witness_path: Path | str,
) -> dict[str, Any]:
    """Generates witness.json containing field element assignments and lookup evaluations.

    Args:
        input_data: Either a 10-feature list, a dict with "input_data" key or feature names,
                    or a path to an existing input.json file.
        compiled_model_path: Path to the compiled Halo2 circuit.
        output_witness_path: Path where witness.json will be saved.

    Returns:
        The generated witness dictionary.
    """
    comp_p = Path(compiled_model_path)
    wit_p = Path(output_witness_path)
    wit_p.parent.mkdir(parents=True, exist_ok=True)

    if not comp_p.is_file():
        raise CircuitError(f"Compiled circuit not found: {comp_p}")

    # Prepare input.json
    temp_input_created = False
    if isinstance(input_data, (str, Path)) and Path(input_data).is_file():
        input_file_path = str(Path(input_data))
    else:
        # Construct input payload
        if isinstance(input_data, dict) and "input_data" in input_data:
            payload = input_data
        elif isinstance(input_data, dict):
            from forensics.ml.features import FEATURE_NAMES
            vec = [float(input_data.get(k, 0.0)) for k in FEATURE_NAMES]
            payload = {"input_data": [vec]}
        elif isinstance(input_data, (list, tuple)):
            if len(input_data) == 1 and isinstance(input_data[0], (list, tuple)):
                vec = [float(v) for v in input_data[0]]
            else:
                vec = [float(v) for v in input_data]
            if len(vec) != 10:
                raise CircuitError(f"Expected 10 feature values, got {len(vec)}")
            payload = {"input_data": [vec]}
        else:
            raise CircuitError(f"Unsupported input data format: {type(input_data)}")

        input_file_path = str(wit_p.parent / f"input_{wit_p.stem}.json")
        with open(input_file_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        temp_input_created = True

    try:
        witness_dict = ezkl.gen_witness(
            input_file_path,
            str(comp_p),
            str(wit_p),
        )
    except Exception as e:
        raise CircuitError(f"EZKL gen_witness failed: {e}") from e
    finally:
        if temp_input_created and os.path.exists(input_file_path):
            try:
                os.remove(input_file_path)
            except OSError:
                pass

    if not wit_p.is_file():
        raise CircuitError(f"Witness file was not created: {wit_p}")

    if not isinstance(witness_dict, dict):
        with open(wit_p, "r", encoding="utf-8") as f:
            witness_dict = json.load(f)

    return witness_dict
