"""ZKML Verifier: Proof Verification & Adversarial Tamper Rejection (Phase 4 / P9).

Responsibilities:
1. Cryptographically verify genuine Halo2 zero-knowledge proofs (pi) via EZKL and BN254 KZG.
2. Verify public instances against feature commitments and output anomaly scores.
3. Enforce model provenance by checking verification key / model hash bindings.
4. Robust tamper rejection: strictly returns False for mutated proof bytes,
   altered instance commitments, spoofed anomaly scores, or corrupted transcripts.
5. Implements Interface Contract 6: verify_proof(proof_path, settings_path, vk_path) -> bool.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
from pathlib import Path
import tempfile
from typing import Any, Sequence

# Windows Environment Guard for EZKL
if "HOME" not in os.environ and "USERPROFILE" in os.environ:
    os.environ["HOME"] = os.environ["USERPROFILE"]

import ezkl

from forensics.zkml.circuit import (
    compute_input_commitment,
    dequantize_score,
    quantize_feature_vector,
    setup_circuit_srs,
)
from forensics.zkml.prover import (
    BN254_SCALAR_MODULUS,
    ZKMLProofResult,
    decode_instance_element,
)

logger = logging.getLogger(__name__)


class ZKMLVerifier:
    """Verifies Halo2 ZKML proofs and rejects adversarial mutations."""

    def __init__(
        self,
        settings_path: Path | str,
        vk_path: Path | str,
        srs_path: Path | str | None = None,
        expected_model_hash: str | None = None,
    ):
        self.settings_path = Path(settings_path)
        self.vk_path = Path(vk_path)
        self.expected_model_hash = expected_model_hash.lower() if expected_model_hash else None

        if not self.settings_path.is_file():
            raise FileNotFoundError(f"Circuit settings not found: {self.settings_path}")
        if not self.vk_path.is_file():
            raise FileNotFoundError(f"Verification key not found: {self.vk_path}")

        # Resolve or locate SRS
        if srs_path and Path(srs_path).is_file():
            self.srs_path = Path(srs_path)
        else:
            candidates = [
                self.vk_path.parent / "kzg.srs",
                self.settings_path.parent / "kzg.srs",
                Path(__file__).resolve().parents[2] / "circuits" / "anomaly_detector_v1" / "kzg.srs",
                Path("circuits/anomaly_detector_v1/kzg.srs"),
                Path("models/zkml/kzg.srs"),
            ]
            found_srs = next((c for c in candidates if c.is_file() and c.stat().st_size > 0), None)
            if found_srs:
                self.srs_path = found_srs
            else:
                # Read logrows and auto-generate local SRS
                with open(self.settings_path, "r", encoding="utf-8") as f:
                    s_data = json.load(f)
                logrows = s_data.get("run_args", {}).get("logrows", 14)
                default_srs = self.settings_path.parent / "kzg.srs"
                self.srs_path = setup_circuit_srs(default_srs, logrows=logrows)

        # Read input scale and model instance shapes from settings
        with open(self.settings_path, "r", encoding="utf-8") as f:
            s_data = json.load(f)
        self.input_scale = s_data.get("run_args", {}).get("input_scale", 7)
        self.model_instance_shapes = s_data.get("model_instance_shapes", [[1, 10], [1, 1]])

    def verify(
        self,
        proof_data: ZKMLProofResult | dict[str, Any] | str | Path,
        feature_vector: Sequence[float] | None = None,
        expected_output_score: float | None = None,
        score_tolerance: float = 0.05,
    ) -> bool:
        """Verifies proof validity against model commitment, inputs, and outputs.

        Returns:
            True if the proof is cryptographically authentic and commitments match.
            False if the proof is mutated, instances are altered, or verification fails.
        """
        temp_proof_file: Path | None = None
        try:
            # 1. Resolve proof file path and loaded proof dictionary
            if isinstance(proof_data, ZKMLProofResult):
                if proof_data.raw_proof_dict:
                    proof_dict = json.loads(json.dumps(proof_data.raw_proof_dict))
                    proof_dict["proof"] = list(proof_data.proof_bytes)
                    proof_dict["hex_proof"] = proof_data.hex_proof
                    proof_dict["instances"] = proof_data.raw_instances
                else:
                    proof_dict = {
                        "protocol": None,
                        "instances": proof_data.raw_instances,
                        "proof": list(proof_data.proof_bytes),
                        "hex_proof": proof_data.hex_proof,
                        "split": None,
                        "pretty_public_inputs": {
                            "rescaled_outputs": [[str(proof_data.output_score)]]
                        },
                    }
                proof_dict["model_hash"] = proof_data.model_hash
                proof_dict["input_commitment"] = proof_data.input_commitment
                proof_dict["output_score"] = proof_data.output_score
                proof_dict["proof_hash"] = proof_data.proof_hash

                # Write temp proof file for ezkl
                fd, tmp_path_str = tempfile.mkstemp(suffix=".json", prefix="verify_proof_")
                os.close(fd)
                temp_proof_file = Path(tmp_path_str)
                with open(temp_proof_file, "w", encoding="utf-8") as f:
                    json.dump(proof_dict, f)
                target_proof_path = temp_proof_file

            elif isinstance(proof_data, dict):
                proof_dict = proof_data
                fd, tmp_path_str = tempfile.mkstemp(suffix=".json", prefix="verify_proof_")
                os.close(fd)
                temp_proof_file = Path(tmp_path_str)
                with open(temp_proof_file, "w", encoding="utf-8") as f:
                    json.dump(proof_dict, f)
                target_proof_path = temp_proof_file

            elif isinstance(proof_data, (str, Path)):
                target_proof_path = Path(proof_data)
                if not target_proof_path.is_file():
                    logger.warning(f"Proof file does not exist: {target_proof_path}")
                    return False
                with open(target_proof_path, "r", encoding="utf-8") as f:
                    proof_dict = json.load(f)
            else:
                logger.warning(f"Unsupported proof_data type: {type(proof_data)}")
                return False

            # 2. Structural sanity check
            proof_ints = proof_dict.get("proof")
            instances = proof_dict.get("instances")
            if proof_ints is None or instances is None:
                logger.warning("Proof missing 'proof' or 'instances' fields")
                return False
            if len(proof_ints) < 64:
                logger.warning("Proof bytes buffer is too short")
                return False
            if not instances or not isinstance(instances, list) or not instances[0]:
                logger.warning("Public instances structure is empty or invalid")
                return False

            expected_instance_count = (
                sum(math.prod(s) for s in self.model_instance_shapes)
                if hasattr(self, "model_instance_shapes")
                else 11
            )
            if len(instances[0]) != expected_instance_count:
                logger.warning(
                    f"Instances length mismatch: expected {expected_instance_count}, got {len(instances[0])}"
                )
                return False

            # 3. Model Hash Verification for all proof input types
            if self.expected_model_hash:
                extracted_hash = None
                if isinstance(proof_data, ZKMLProofResult):
                    extracted_hash = proof_data.model_hash
                elif "model_hash" in proof_dict and proof_dict["model_hash"] is not None:
                    extracted_hash = proof_dict.get("model_hash")
                elif "metadata" in proof_dict and isinstance(proof_dict["metadata"], dict):
                    extracted_hash = proof_dict["metadata"].get("model_hash")

                if extracted_hash and str(extracted_hash).lower() != self.expected_model_hash:
                    logger.warning(
                        f"Model hash mismatch: expected {self.expected_model_hash}, got {extracted_hash}"
                    )
                    return False

            # 4. Cryptographic Output Anomaly Score Verification
            raw_instances = instances[0]
            try:
                raw_out_hex = raw_instances[-1]
                q_out = decode_instance_element(raw_out_hex)
                proven_output_score = dequantize_score(q_out, scale_bits=self.input_scale)
            except Exception as e:
                logger.warning(f"Failed to decode cryptographic output instance: {e}")
                return False

            # Check expected_output_score
            if expected_output_score is not None:
                if abs(proven_output_score - expected_output_score) > score_tolerance:
                    logger.warning(
                        f"Proven score {proven_output_score} deviates from expected {expected_output_score}"
                    )
                    return False

            # Cross-validate against ZKMLProofResult.output_score
            if isinstance(proof_data, ZKMLProofResult):
                if abs(proof_data.output_score - proven_output_score) > score_tolerance:
                    logger.warning(
                        f"ZKMLProofResult.output_score {proof_data.output_score} contradicts proven score {proven_output_score}"
                    )
                    return False

            # Cross-validate against proof_dict.output_score if present
            if "output_score" in proof_dict and proof_dict["output_score"] is not None:
                try:
                    dict_score = float(proof_dict["output_score"])
                    if abs(dict_score - proven_output_score) > score_tolerance:
                        logger.warning(
                            f"proof_dict.output_score {dict_score} contradicts proven score {proven_output_score}"
                        )
                        return False
                except (ValueError, TypeError):
                    return False

            # Reject proofs where pretty_public_inputs is present but inconsistent with cryptographic public instances
            pretty = proof_dict.get("pretty_public_inputs")
            if isinstance(pretty, dict):
                rescaled_outs = pretty.get("rescaled_outputs", [[]])
                if rescaled_outs and rescaled_outs[0]:
                    try:
                        pretty_score = float(rescaled_outs[0][0])
                        if abs(pretty_score - proven_output_score) > score_tolerance:
                            logger.warning(
                                f"pretty_public_inputs score {pretty_score} contradicts proven score {proven_output_score}"
                            )
                            return False
                    except (ValueError, TypeError):
                        return False

            # 5. Cryptographic Input Feature Vector Verification (all input types)
            if feature_vector is not None:
                q_expected = quantize_feature_vector(feature_vector, scale_bits=self.input_scale)
                if len(raw_instances) < len(q_expected):
                    logger.warning("Instances array shorter than expected input feature vector")
                    return False

                try:
                    actual_q = [decode_instance_element(h) for h in raw_instances[:len(q_expected)]]
                except Exception as e:
                    logger.warning(f"Failed to decode input instances: {e}")
                    return False

                if actual_q != q_expected:
                    logger.warning("Public instances do not match quantized feature vector")
                    return False

                expected_comm = compute_input_commitment(feature_vector, scale_bits=self.input_scale)
                if isinstance(proof_data, ZKMLProofResult):
                    if proof_data.input_commitment != expected_comm:
                        logger.warning("Input commitment mismatch on ZKMLProofResult")
                        return False

                if "input_commitment" in proof_dict and proof_dict["input_commitment"] != expected_comm:
                    logger.warning("Input commitment mismatch on proof_dict")
                    return False

            # 6. Native EZKL Halo2 Cryptographic Verification
            res = ezkl.verify(
                str(target_proof_path),
                str(self.settings_path),
                str(self.vk_path),
                str(self.srs_path),
            )
            return bool(res)

        except Exception as e:
            # Any cryptographic failure, transcript error, or constraint violation
            logger.info(f"Verification rejected (expected for tampered proofs): {type(e).__name__}: {e}")
            return False

        finally:
            if temp_proof_file and temp_proof_file.exists():
                try:
                    temp_proof_file.unlink()
                except OSError:
                    pass


def verify_proof(
    proof_path: Path | str,
    settings_path: Path | str,
    vk_path: Path | str,
    srs_path: Path | str | None = None,
) -> bool:
    """Interface Contract 6: Cryptographically verifies a Halo2 ZKML proof.

    Guarantees:
    - Returns True for authentic proofs.
    - Returns False for tampered proofs, altered instances, or corrupted inputs.
    - Never emits mock proofs.
    """
    try:
        verifier = ZKMLVerifier(settings_path=settings_path, vk_path=vk_path, srs_path=srs_path)
        return verifier.verify(proof_data=proof_path)
    except Exception as e:
        logger.info(f"verify_proof caught rejection: {e}")
        return False
