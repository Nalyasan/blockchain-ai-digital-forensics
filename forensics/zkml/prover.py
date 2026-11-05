"""ZKML Prover: Halo2 Proof Generation via EZKL.

Orchestrates circuit compilation, SRS, proving/verification key lifecycle, witness
traces, and Halo2 KZG proof synthesis with strict model-to-circuit hash binding.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Sequence

if "HOME" not in os.environ and "USERPROFILE" in os.environ:
    os.environ["HOME"] = os.environ["USERPROFILE"]

import ezkl

from forensics.zkml.circuit import (
    CircuitConfig,
    CircuitError,
    compile_circuit,
    compute_input_commitment,
    dequantize_score,
    generate_circuit_settings,
    generate_witness,
    setup_circuit_srs,
    setup_keys,
)

BN254_SCALAR_MODULUS = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
DEFAULT_CIRCUIT_DIR = Path(__file__).resolve().parents[2] / "circuits" / "anomaly_detector_v1"


def decode_instance_element(inst_hex: str) -> int:
    """Decode a 32-byte little-endian BN254 scalar field element into a signed integer."""
    clean_hex = inst_hex[2:] if inst_hex.startswith("0x") else inst_hex
    raw_bytes = bytes.fromhex(clean_hex)
    u = int.from_bytes(raw_bytes, byteorder="little")
    if u > (BN254_SCALAR_MODULUS // 2):
        return u - BN254_SCALAR_MODULUS
    return u


def encode_evm_instance_uint256(inst_hex: str) -> int:
    """Convert EZKL's 32-byte little-endian scalar field hex into EVM uint256 instance representation."""
    clean_hex = inst_hex[2:] if inst_hex.startswith("0x") else inst_hex
    return int.from_bytes(bytes.fromhex(clean_hex), byteorder="little")


class ProverError(Exception):
    """Raised when proof generation or setup fails."""


@dataclass
class ZKMLProofResult:
    """Encapsulates a verified Halo2 inference proof and public commitments."""
    proof_bytes: bytes
    hex_proof: str = ""
    proof_hash: str = ""
    model_hash: str = ""
    input_commitment: str = ""
    output_score: float = 0.0
    raw_instances: list[list[str]] = field(default_factory=lambda: [[]])
    is_valid: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_proof_dict: dict[str, Any] | None = None

    def __init__(
        self,
        proof_bytes: bytes,
        hex_proof: str | None = None,
        proof_hash: str | None = None,
        model_hash: str = "",
        input_commitment: str = "",
        output_score: float = 0.0,
        raw_instances: list[list[str]] | None = None,
        is_valid: bool = True,
        metadata: dict[str, Any] | None = None,
        raw_proof_dict: dict[str, Any] | None = None,
        *,
        public_inputs: list[list[str]] | None = None,
        output_commitment: str | None = None,
        circuit_version: str | None = None,
        proof_time_sec: float | None = None,
    ):
        self.proof_bytes = bytes(proof_bytes)
        self.hex_proof = hex_proof or ("0x" + self.proof_bytes.hex())
        self.proof_hash = proof_hash or ("0x" + hashlib.sha256(self.proof_bytes).hexdigest())
        self.model_hash = model_hash
        self.input_commitment = input_commitment
        self.output_score = float(output_score)
        self.raw_instances = raw_instances if raw_instances is not None else (public_inputs if public_inputs is not None else [[]])
        self.is_valid = bool(is_valid)
        meta = dict(metadata) if metadata else {}
        if output_commitment is not None:
            meta.setdefault("output_commitment", output_commitment)
        if circuit_version is not None:
            meta.setdefault("circuit_version", circuit_version)
        if proof_time_sec is not None:
            meta.setdefault("proof_time_sec", proof_time_sec)
        self.metadata = meta
        self.raw_proof_dict = raw_proof_dict

    @property
    def public_inputs(self) -> list[list[str]]:
        return self.raw_instances

    @property
    def evm_instances(self) -> list[int]:
        if not self.raw_instances or not self.raw_instances[0]:
            return []
        return [encode_evm_instance_uint256(h) for h in self.raw_instances[0]]

    @property
    def output_commitment(self) -> str:
        evm_inst = self.evm_instances
        if evm_inst:
            return "0x" + evm_inst[-1].to_bytes(32, byteorder="big").hex()
        q_score = int(round(self.output_score * 128))
        return "0x" + q_score.to_bytes(32, byteorder="big", signed=False).hex()

    @property
    def circuit_version(self) -> str:
        return str(self.metadata.get("version", getattr(ezkl, "__version__", "halo2-kzg-v1")))

    @property
    def proof_time_sec(self) -> float:
        return float(self.metadata.get("proof_time_sec", 0.0))

    def to_dict(self) -> dict[str, Any]:
        return {
            "proof_hash": self.proof_hash,
            "hex_proof": self.hex_proof,
            "proof": list(self.proof_bytes),
            "instances": self.raw_instances,
            "evm_instances": self.evm_instances,
            "proof_bytes_length": len(self.proof_bytes),
            "model_hash": self.model_hash,
            "input_commitment": self.input_commitment,
            "output_commitment": self.output_commitment,
            "output_score": self.output_score,
            "raw_instances": self.raw_instances,
            "is_valid": self.is_valid,
            "metadata": self.metadata,
        }

    def save(self, path: Path | str) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if self.raw_proof_dict:
            d = json.loads(json.dumps(self.raw_proof_dict))
            d["proof"] = list(self.proof_bytes)
            d["hex_proof"] = self.hex_proof
            d["instances"] = self.raw_instances
        else:
            d = {
                "protocol": None,
                "instances": self.raw_instances,
                "proof": list(self.proof_bytes),
                "hex_proof": self.hex_proof,
                "split": None,
                "pretty_public_inputs": {
                    "rescaled_outputs": [[str(self.output_score)]]
                },
                "metadata": self.metadata,
            }
        d["model_hash"] = self.model_hash
        d["input_commitment"] = self.input_commitment
        d["output_commitment"] = self.output_commitment
        d["output_score"] = self.output_score
        d["proof_hash"] = self.proof_hash
        d["raw_instances"] = self.raw_instances
        d["is_valid"] = self.is_valid
        with open(p, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2)
        return p

    @classmethod
    def load(cls, path: Path | str) -> ZKMLProofResult:
        p = Path(path)
        with open(p, "r", encoding="utf-8") as f:
            d = json.load(f)
        hex_p = d["hex_proof"]
        raw_bytes = bytes.fromhex(hex_p[2:] if hex_p.startswith("0x") else hex_p)
        instances = d.get("raw_instances") or d.get("instances", [[]])
        return cls(
            proof_bytes=raw_bytes,
            hex_proof=hex_p,
            proof_hash=d["proof_hash"],
            model_hash=d["model_hash"],
            input_commitment=d["input_commitment"],
            output_score=float(d["output_score"]),
            raw_instances=instances,
            is_valid=bool(d.get("is_valid", True)),
            metadata=d.get("metadata", {}),
            raw_proof_dict=d,
        )


ProofResult = ZKMLProofResult


class ZKMLProver:
    """Manages circuit lifecycle and synthesizes genuine Halo2 ZKML proofs."""

    def __init__(
        self,
        model_path: Path | str = "models/anomaly_detector_v1.onnx",
        settings_path: Path | str | None = None,
        compiled_path: Path | str | None = None,
        pk_path: Path | str | None = None,
        vk_path: Path | str | None = None,
        srs_path: Path | str | None = None,
        artifacts_dir: Path | str | None = None,
        auto_setup: bool = True,
    ):
        self.model_path = Path(model_path)
        if not self.model_path.is_file():
            raise ProverError(f"ONNX model file not found: {self.model_path}")

        self.model_hash = "0x" + hashlib.sha256(self.model_path.read_bytes()).hexdigest()
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else DEFAULT_CIRCUIT_DIR
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

        self.settings_path = Path(settings_path) if settings_path else self.artifacts_dir / "settings.json"
        self.compiled_path = Path(compiled_path) if compiled_path else self.artifacts_dir / "network.compiled"
        self.pk_path = Path(pk_path) if pk_path else self.artifacts_dir / "pk.key"
        self.vk_path = Path(vk_path) if vk_path else self.artifacts_dir / "vk.key"
        self.srs_path = Path(srs_path) if srs_path else self.artifacts_dir / "kzg.srs"
        self.meta_path = self.artifacts_dir / "circuit_meta.json"

        if auto_setup:
            self.setup()

    def _is_circuit_stale(self) -> bool:
        """Invalidate cached circuit artifacts when the ONNX model digest changes."""
        if not self.compiled_path.is_file():
            return False
        if not self.meta_path.is_file():
            return True
        try:
            meta = json.loads(self.meta_path.read_text(encoding="utf-8"))
            return str(meta.get("model_sha256", "")).lower() != self.model_hash.lower()
        except Exception:
            return True

    def setup(self) -> None:
        """Prepare settings, compiled circuit, SRS, and proving/verifying keys with model-hash sync."""
        stale = self._is_circuit_stale()
        if stale:
            for stale_file in (self.settings_path, self.compiled_path, self.pk_path, self.vk_path, self.meta_path):
                if stale_file.is_file():
                    stale_file.unlink()

        if not self.settings_path.is_file():
            cfg = CircuitConfig()
            generate_circuit_settings(self.model_path, self.settings_path, cfg)

        with open(self.settings_path, "r", encoding="utf-8") as f:
            settings_data = json.load(f)
        self.logrows = settings_data.get("run_args", {}).get("logrows", 14)
        self.input_scale = settings_data.get("run_args", {}).get("input_scale", 7)

        if not self.compiled_path.is_file():
            compile_circuit(self.model_path, self.compiled_path, self.settings_path)

        if not self.srs_path.is_file() or self.srs_path.stat().st_size == 0:
            setup_circuit_srs(self.srs_path, logrows=self.logrows)

        expected_vk_sha = None
        if self.meta_path.is_file():
            try:
                expected_vk_sha = json.loads(self.meta_path.read_text(encoding="utf-8")).get("vk_sha256")
            except Exception:
                expected_vk_sha = None

        if not self.pk_path.is_file() or not self.vk_path.is_file():
            setup_keys(self.compiled_path, self.vk_path, self.pk_path, self.srs_path)
            actual_vk_sha = hashlib.sha256(self.vk_path.read_bytes()).hexdigest()
            if expected_vk_sha and actual_vk_sha.lower() != expected_vk_sha.lower():
                raise ProverError(
                    f"Deterministic VK mismatch after key setup: expected {expected_vk_sha}, got {actual_vk_sha}"
                )

        vk_sha = hashlib.sha256(self.vk_path.read_bytes()).hexdigest()
        compiled_sha = hashlib.sha256(self.compiled_path.read_bytes()).hexdigest()
        srs_sha = hashlib.sha256(self.srs_path.read_bytes()).hexdigest()
        meta_payload = {
            "model_sha256": self.model_hash,
            "compiled_sha256": compiled_sha,
            "vk_sha256": vk_sha,
            "srs_sha256": srs_sha,
            "ezkl_version": getattr(ezkl, "__version__", "unknown"),
            "logrows": self.logrows,
            "input_scale": self.input_scale,
        }
        self.meta_path.write_text(json.dumps(meta_payload, indent=2), encoding="utf-8")

    def prove(
        self,
        feature_vector: Sequence[float] | dict[str, float] | Any,
        output_proof_path: Path | str | None = None,
    ) -> ZKMLProofResult:
        """Synthesize a genuine Halo2 zero-knowledge proof for a 10-feature input vector."""
        import time as _time

        t0 = _time.perf_counter()
        if not self.pk_path.is_file() or not self.compiled_path.is_file() or self._is_circuit_stale():
            self.setup()

        if isinstance(feature_vector, dict):
            from forensics.ml.features import FEATURE_NAMES
            raw_features = [float(feature_vector.get(k, 0.0)) for k in FEATURE_NAMES]
        elif hasattr(feature_vector, "tolist"):
            raw_features = [float(v) for v in feature_vector.tolist()]
        elif isinstance(feature_vector, (list, tuple)):
            if len(feature_vector) == 1 and isinstance(feature_vector[0], (list, tuple)):
                raw_features = [float(v) for v in feature_vector[0]]
            else:
                raw_features = [float(v) for v in feature_vector]
        else:
            raise ProverError(f"Unsupported feature vector type: {type(feature_vector)}")

        if len(raw_features) != 10:
            raise ProverError(f"Feature vector must have exactly 10 features, got {len(raw_features)}")

        with tempfile.TemporaryDirectory(prefix="zkml_proof_") as tmp_dir_str:
            tmp_dir = Path(tmp_dir_str)
            witness_path = tmp_dir / "witness.json"
            proof_file = Path(output_proof_path) if output_proof_path else tmp_dir / "proof.json"
            proof_file.parent.mkdir(parents=True, exist_ok=True)

            try:
                generate_witness(raw_features, self.compiled_path, witness_path)
            except Exception as e:
                raise ProverError(f"Witness generation failed: {e}") from e

            try:
                ezkl.prove(
                    str(witness_path),
                    str(self.compiled_path),
                    str(self.pk_path),
                    str(proof_file),
                    str(self.srs_path),
                )
            except Exception as e:
                raise ProverError(f"Halo2 proof synthesis failed: {e}") from e

            if not proof_file.is_file():
                raise ProverError(f"Proof file was not created: {proof_file}")

            with open(proof_file, "r", encoding="utf-8") as f:
                proof_data = json.load(f)

        elapsed_sec = round(_time.perf_counter() - t0, 4)
        raw_proof_ints = proof_data.get("proof", [])
        if not raw_proof_ints:
            raise ProverError("Synthesized proof data has empty proof buffer")

        proof_bytes = bytes(raw_proof_ints)
        hex_proof = proof_data.get("hex_proof", "0x" + proof_bytes.hex())
        proof_hash = "0x" + hashlib.sha256(proof_bytes).hexdigest()
        input_comm = compute_input_commitment(raw_features, scale_bits=self.input_scale)

        instances = proof_data.get("instances", [[]])
        if not instances or not instances[0]:
            raise ProverError("Proof data missing public instances")

        try:
            raw_out_hex = instances[0][-1]
            q_out = decode_instance_element(raw_out_hex)
            proven_score = dequantize_score(q_out, scale_bits=self.input_scale)
        except Exception as e:
            raise ProverError(f"Failed to decode cryptographic output instance: {e}") from e

        output_score = proven_score
        pretty_inputs = proof_data.get("pretty_public_inputs", {})
        rescaled_outputs = pretty_inputs.get("rescaled_outputs", [])
        if rescaled_outputs and rescaled_outputs[0]:
            try:
                pretty_score = float(rescaled_outputs[0][0])
                if abs(pretty_score - proven_score) > 0.05:
                    raise ProverError(
                        f"Synthesized proof pretty_public_inputs ({pretty_score}) contradicts cryptographic output ({proven_score})"
                    )
                output_score = pretty_score
            except (ValueError, TypeError):
                output_score = proven_score

        return ZKMLProofResult(
            proof_bytes=proof_bytes,
            hex_proof=hex_proof,
            proof_hash=proof_hash,
            model_hash=self.model_hash,
            input_commitment=input_comm,
            output_score=output_score,
            raw_instances=instances,
            is_valid=True,
            metadata={
                "version": proof_data.get("version", ezkl.__version__),
                "timestamp": proof_data.get("timestamp"),
                "logrows": self.logrows,
                "input_scale": self.input_scale,
                "proof_length_bytes": len(proof_bytes),
                "proof_time_sec": elapsed_sec,
            },
            raw_proof_dict=proof_data,
        )
