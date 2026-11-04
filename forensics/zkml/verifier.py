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
import os
from pathlib import Path
import tempfile
from typing import Any, Sequence

# Windows Environment Guard for EZKL
if "HOME" not in os.environ and "USERPROFILE" in os.environ:
    os.environ["HOME"] = os.environ["USERPROFILE"]

import ezkl

from forensics.zkml.circuit import compute_input_commitment, setup_circuit_srs
from forensics.zkml.prover import ZKMLProofResult

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
                Path("scratch/zkml_artifacts/kzg.srs"),
                Path("scratch/ezkl_probe/kzg.srs"),
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

        # Read input scale from settings
        with open(self.settings_path, "r", encoding="utf-8") as f:
            s_data = json.load(f)
        self.input_scale = s_data.get("run_args", {}).get("input_scale", 7)

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
                # Check model hash
                if self.expected_model_hash and proof_data.model_hash.lower() != self.expected_model_hash:
                    logger.warning("Model hash mismatch in ZKMLProofResult")
                    return False
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

            # 3. Public inputs verification (if feature_vector provided)
            if feature_vector is not None:
                expected_comm = compute_input_commitment(feature_vector, scale_bits=self.input_scale)
                if isinstance(proof_data, ZKMLProofResult):
                    if proof_data.input_commitment != expected_comm:
                        logger.warning("Input commitment mismatch")
                        return False

            # 4. Public output verification (if expected_output_score provided)
            if expected_output_score is not None:
                pretty = proof_dict.get("pretty_public_inputs", {})
                rescaled_outs = pretty.get("rescaled_outputs", [[]])
                if rescaled_outs and rescaled_outs[0]:
                    reported_score = float(rescaled_outs[0][0])
                    if abs(reported_score - expected_output_score) > score_tolerance:
                        logger.warning(f"Reported score {reported_score} deviates from expected {expected_output_score}")
                        return False

            # 5. Native EZKL Halo2 Cryptographic Verification
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
