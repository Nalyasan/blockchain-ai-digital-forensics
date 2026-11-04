"""Adversarial Tamper Challenger Test Suite for Phase 4 / P9 ZKML Verifiable Inference.

Author: challenger_M4_1 (P9 ZKML Adversarial Tamper Challenger)
Roles: critic, specialist

Mandatory Challenge Dimensions:
1. Scenario 1: Bit-flipped proof bytes (flip arbitrary bits in Halo2 proof).
2. Scenario 2: Altered input features (tamper with input vector after witness/proof gen).
3. Scenario 3: Altered public instances (tamper with quantized public instance outputs).
4. Scenario 4: Spoofed anomaly score (falsify anomaly score in public attestation).
5. Scenario 5: Model hash mismatch (verify against altered or different model).
6. Scenario 6: Truncated or empty proof bytes.
7. Scenario 7: Random non-Halo2 byte arrays.
8. Genuine proof reliability and determinism across multiple vectors.
9. Database bitwise invariance for real_p4.db and forensics.db.
"""
from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Sequence
import pytest

from forensics.ml.model import CompactAnomalyMLP, load_default_model
from forensics.zkml import (
    CircuitConfig,
    ZKMLProofResult,
    ZKMLProver,
    ZKMLVerifier,
    compute_input_commitment,
    export_model_to_zkml_onnx,
    verify_proof,
)

# Reference canonical DB SHA-256 hashes
EXPECTED_REAL_P4_SHA256 = "6bd9aed48ac2742d0862198bff65994861244ec681dc8abeb3e6f771e7808c97"
EXPECTED_FORENSICS_SHA256 = "3f2b0dfc772a96ff6ea57c65807b5b6b9a20fcf74c409c6f222fcff29f1ef001"


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture(scope="module")
def default_model_path() -> Path:
    p = Path("models/anomaly_detector_v1.onnx")
    assert p.is_file(), f"Model missing: {p}"
    return p


@pytest.fixture(scope="module")
def zkml_prover(default_model_path) -> ZKMLProver:
    return ZKMLProver(
        model_path=default_model_path,
        artifacts_dir=Path("scratch/zkml_artifacts"),
        auto_setup=True,
    )


@pytest.fixture(scope="module")
def canonical_feature_vector() -> list[float]:
    return [1.0, 0.0, 2.0, 15.5, 12.3, 0.95, 2.0, 1.0, 0.5, 0.8]


@pytest.fixture(scope="module")
def genuine_proof_result(zkml_prover, canonical_feature_vector) -> ZKMLProofResult:
    return zkml_prover.prove(canonical_feature_vector)


@pytest.fixture(scope="module")
def zkml_verifier(zkml_prover) -> ZKMLVerifier:
    return ZKMLVerifier(
        settings_path=zkml_prover.settings_path,
        vk_path=zkml_prover.vk_path,
        srs_path=zkml_prover.srs_path,
        expected_model_hash=zkml_prover.model_hash,
    )


# ==============================================================================
# Scenario 1: Bit-Flipped Proof Bytes
# ==============================================================================

class TestScenario1BitFlippedProofBytes:
    """Stress tests verification rejection against bit mutations across the proof buffer."""

    def test_single_bit_flips_at_various_offsets(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult, canonical_feature_vector: list[float]
    ):
        proof_len = len(genuine_proof_result.proof_bytes)
        offsets = [0, 1, 10, 100, 1000, 2752, 5000, proof_len - 1]
        bits = [0, 3, 7]

        for off in offsets:
            for bit in bits:
                tb = bytearray(genuine_proof_result.proof_bytes)
                tb[off] ^= (1 << bit)
                tampered = replace(
                    genuine_proof_result,
                    proof_bytes=bytes(tb),
                    hex_proof="0x" + bytes(tb).hex(),
                )
                assert zkml_verifier.verify(tampered, feature_vector=canonical_feature_vector) is False, (
                    f"Bit-flip at offset {off} bit {bit} was not rejected!"
                )

    def test_multiple_distributed_bit_flips(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult, canonical_feature_vector: list[float]
    ):
        tb = bytearray(genuine_proof_result.proof_bytes)
        # Flip 10 distributed bits
        for i in range(10):
            tb[(i * 500) % len(tb)] ^= 0x01
        tampered = replace(
            genuine_proof_result,
            proof_bytes=bytes(tb),
            hex_proof="0x" + bytes(tb).hex(),
        )
        assert zkml_verifier.verify(tampered, feature_vector=canonical_feature_vector) is False

    def test_contract6_verify_proof_rejects_bit_flipped_file(
        self, zkml_prover: ZKMLProver, genuine_proof_result: ZKMLProofResult, tmp_path: Path
    ):
        proof_file = tmp_path / "bit_flipped_proof.json"
        tb = bytearray(genuine_proof_result.proof_bytes)
        tb[50] ^= 0x01

        d = dict(genuine_proof_result.raw_proof_dict)
        d["proof"] = list(tb)
        d["hex_proof"] = "0x" + bytes(tb).hex()
        with open(proof_file, "w", encoding="utf-8") as f:
            json.dump(d, f)

        ok = verify_proof(
            proof_path=proof_file,
            settings_path=zkml_prover.settings_path,
            vk_path=zkml_prover.vk_path,
            srs_path=zkml_prover.srs_path,
        )
        assert ok is False


# ==============================================================================
# Scenario 2: Altered Input Features
# ==============================================================================

class TestScenario2AlteredInputFeatures:
    """Stress tests rejection when input features differ from circuit witness."""

    def test_perturbed_single_feature_rejected(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult, canonical_feature_vector: list[float]
    ):
        for idx in range(10):
            perturbed = list(canonical_feature_vector)
            perturbed[idx] += 0.05
            assert zkml_verifier.verify(genuine_proof_result, feature_vector=perturbed) is False

    def test_zeroed_features_rejected(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult
    ):
        assert zkml_verifier.verify(genuine_proof_result, feature_vector=[0.0] * 10) is False

    def test_inverted_features_rejected(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult, canonical_feature_vector: list[float]
    ):
        assert zkml_verifier.verify(genuine_proof_result, feature_vector=canonical_feature_vector[::-1]) is False

    def test_proof_file_rejects_altered_feature_vector(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult, tmp_path: Path
    ):
        """Verifies that passing a proof file path against an altered feature vector returns False."""
        proof_file = tmp_path / "proof_for_input_check.json"
        genuine_proof_result.save(proof_file)

        altered_vec = [0.0] * 10
        # Must be rejected because proof_file was generated for canonical_feature_vector
        assert zkml_verifier.verify(proof_file, feature_vector=altered_vec) is False

    def test_proof_dict_rejects_altered_feature_vector(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult
    ):
        """Verifies that passing a proof dict against an altered feature vector returns False."""
        proof_dict = genuine_proof_result.to_dict()
        altered_vec = [0.0] * 10
        assert zkml_verifier.verify(proof_dict, feature_vector=altered_vec) is False


# ==============================================================================
# Scenario 3: Altered Public Instances
# ==============================================================================

class TestScenario3AlteredPublicInstances:
    """Stress tests rejection when public instance elements are manipulated."""

    def test_mutate_each_instance_element(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult, canonical_feature_vector: list[float]
    ):
        for idx in range(len(genuine_proof_result.raw_instances[0])):
            inst_copy = copy.deepcopy(genuine_proof_result.raw_instances)
            orig = inst_copy[0][idx]
            # Mutate first hex digit
            mut_digit = "1" if orig[0] != "1" else "2"
            inst_copy[0][idx] = mut_digit + orig[1:]

            tampered = replace(genuine_proof_result, raw_instances=inst_copy)
            assert zkml_verifier.verify(tampered, feature_vector=canonical_feature_vector) is False

    def test_truncate_public_instances(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult, canonical_feature_vector: list[float]
    ):
        inst_copy = [genuine_proof_result.raw_instances[0][:5]]
        tampered = replace(genuine_proof_result, raw_instances=inst_copy)
        assert zkml_verifier.verify(tampered, feature_vector=canonical_feature_vector) is False

    def test_extra_public_instance_element(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult, canonical_feature_vector: list[float]
    ):
        inst_copy = [genuine_proof_result.raw_instances[0] + ["00" * 32]]
        tampered = replace(genuine_proof_result, raw_instances=inst_copy)
        assert zkml_verifier.verify(tampered, feature_vector=canonical_feature_vector) is False

    def test_contract6_verify_proof_rejects_altered_instances(
        self, zkml_prover: ZKMLProver, genuine_proof_result: ZKMLProofResult, tmp_path: Path
    ):
        proof_file = tmp_path / "tampered_instances.json"
        d = dict(genuine_proof_result.raw_proof_dict)
        d["instances"] = [["00" * 32] * 11]
        with open(proof_file, "w", encoding="utf-8") as f:
            json.dump(d, f)

        ok = verify_proof(
            proof_path=proof_file,
            settings_path=zkml_prover.settings_path,
            vk_path=zkml_prover.vk_path,
            srs_path=zkml_prover.srs_path,
        )
        assert ok is False


# ==============================================================================
# Scenario 4: Spoofed Anomaly Score
# ==============================================================================

class TestScenario4SpoofedAnomalyScore:
    """Stress tests rejection when output anomaly score is spoofed or manipulated."""

    def test_spoofed_expected_score_rejected(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult, canonical_feature_vector: list[float]
    ):
        # Actual proven score is 1.0; verifying with expected score 0.05 or 0.0 must fail
        assert zkml_verifier.verify(
            genuine_proof_result,
            feature_vector=canonical_feature_vector,
            expected_output_score=0.05,
        ) is False
        assert zkml_verifier.verify(
            genuine_proof_result,
            feature_vector=canonical_feature_vector,
            expected_output_score=0.0,
        ) is False

    def test_tampered_zkml_proof_result_output_score_rejected(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult, canonical_feature_vector: list[float]
    ):
        """Attacker modifies output_score in ZKMLProofResult to 0.0 (claiming benign).

        Verifier must reject because proven score in instances[0][-1] is 1.0.
        """
        tampered = replace(genuine_proof_result, output_score=0.0)
        assert zkml_verifier.verify(tampered, feature_vector=canonical_feature_vector) is False

    def test_tampered_pretty_public_inputs_rejected(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult
    ):
        """Attacker modifies pretty_public_inputs to claim 0.05 with expected=0.05.

        Verifier must reject because cryptographic instance in instances[0][-1] is 1.0 (128).
        """
        d = copy.deepcopy(genuine_proof_result.raw_proof_dict)
        d["pretty_public_inputs"]["rescaled_outputs"] = [["0.05"]]
        assert zkml_verifier.verify(d, expected_output_score=0.05) is False

    def test_missing_pretty_public_inputs_rejected_when_expected_score_provided(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult
    ):
        """Attacker deletes pretty_public_inputs entirely and passes expected_output_score=0.0.

        Verifier must reject because actual output is 1.0.
        """
        d = copy.deepcopy(genuine_proof_result.raw_proof_dict)
        if "pretty_public_inputs" in d:
            del d["pretty_public_inputs"]
        assert zkml_verifier.verify(d, expected_output_score=0.0) is False

    def test_tampered_instance_output_with_matching_pretty_rejected_cryptographically(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult
    ):
        """Attacker modifies instances[0][10] AND pretty_public_inputs to 0.05.

        ezkl.verify must reject because proof bytes do not match modified instance.
        """
        d = copy.deepcopy(genuine_proof_result.raw_proof_dict)
        d["pretty_public_inputs"]["rescaled_outputs"] = [["0.05"]]
        d["instances"][0][10] = "0600000000000000000000000000000000000000000000000000000000000000"
        assert zkml_verifier.verify(d, expected_output_score=0.05) is False


# ==============================================================================
# Scenario 5: Model Hash Mismatch
# ==============================================================================

class TestScenario5ModelHashMismatch:
    """Stress tests rejection against model substitution and verification key mismatches."""

    def test_mismatched_model_hash_on_result_rejected(
        self, zkml_prover: ZKMLProver, genuine_proof_result: ZKMLProofResult, canonical_feature_vector: list[float]
    ):
        wrong_v = ZKMLVerifier(
            settings_path=zkml_prover.settings_path,
            vk_path=zkml_prover.vk_path,
            srs_path=zkml_prover.srs_path,
            expected_model_hash="0x" + "aa" * 32,
        )
        assert wrong_v.verify(genuine_proof_result, feature_vector=canonical_feature_vector) is False

    def test_mismatched_model_hash_on_file_rejected(
        self, zkml_prover: ZKMLProver, genuine_proof_result: ZKMLProofResult, tmp_path: Path
    ):
        """Verifies that a proof file is rejected when verifier specifies an expected model hash."""
        proof_file = tmp_path / "model_check_proof.json"
        d = dict(genuine_proof_result.raw_proof_dict)
        d["model_hash"] = genuine_proof_result.model_hash
        with open(proof_file, "w", encoding="utf-8") as f:
            json.dump(d, f)

        wrong_v = ZKMLVerifier(
            settings_path=zkml_prover.settings_path,
            vk_path=zkml_prover.vk_path,
            srs_path=zkml_prover.srs_path,
            expected_model_hash="0x" + "aa" * 32,
        )
        assert wrong_v.verify(proof_file) is False

    def test_cross_model_vk_rejection(
        self, zkml_prover: ZKMLProver, genuine_proof_result: ZKMLProofResult, tmp_path: Path
    ):
        """Verifies that proof generated with Model 1 fails verification with Model 2 VK."""
        # 1. Create perturbed model
        m2 = CompactAnomalyMLP()
        onnx2 = tmp_path / "model2.onnx"
        export_model_to_zkml_onnx(m2, onnx2)

        # 2. Setup prover/verifier for Model 2
        p2 = ZKMLProver(model_path=onnx2, artifacts_dir=tmp_path / "artifacts2")
        v2 = ZKMLVerifier(p2.settings_path, p2.vk_path, p2.srs_path)

        assert p2.model_hash != zkml_prover.model_hash

        # 3. Verify genuine proof from Model 1 against Model 2 verifier -> MUST FAIL
        assert v2.verify(genuine_proof_result) is False


# ==============================================================================
# Scenario 6: Truncated or Empty Proof Bytes
# ==============================================================================

class TestScenario6TruncatedOrEmptyProofBytes:
    """Stress tests rejection against truncated or empty proof byte streams."""

    @pytest.mark.parametrize(
        "trunc_len",
        [0, 1, 16, 32, 63, 64, 128, 500, 2752, 5503],
    )
    def test_truncated_proof_bytes_rejected(
        self,
        zkml_verifier: ZKMLVerifier,
        genuine_proof_result: ZKMLProofResult,
        canonical_feature_vector: list[float],
        trunc_len: int,
    ):
        tb = genuine_proof_result.proof_bytes[:trunc_len]
        tampered = replace(
            genuine_proof_result,
            proof_bytes=tb,
            hex_proof="0x" + tb.hex(),
        )
        assert zkml_verifier.verify(tampered, feature_vector=canonical_feature_vector) is False

    @pytest.mark.parametrize(
        "trunc_len",
        [0, 1, 63, 64, 5503],
    )
    def test_contract6_truncated_proof_file_rejected(
        self, zkml_prover: ZKMLProver, genuine_proof_result: ZKMLProofResult, tmp_path: Path, trunc_len: int
    ):
        proof_file = tmp_path / f"trunc_{trunc_len}.json"
        tb = genuine_proof_result.proof_bytes[:trunc_len]
        d = dict(genuine_proof_result.raw_proof_dict)
        d["proof"] = list(tb)
        d["hex_proof"] = "0x" + tb.hex()
        with open(proof_file, "w", encoding="utf-8") as f:
            json.dump(d, f)

        ok = verify_proof(
            proof_path=proof_file,
            settings_path=zkml_prover.settings_path,
            vk_path=zkml_prover.vk_path,
            srs_path=zkml_prover.srs_path,
        )
        assert ok is False


# ==============================================================================
# Scenario 7: Random Non-Halo2 Byte Arrays
# ==============================================================================

class TestScenario7RandomNonHalo2ByteArrays:
    """Stress tests rejection against random non-cryptographic byte streams."""

    @pytest.mark.parametrize(
        "pattern_name,byte_payload",
        [
            ("urandom_5504", os.urandom(5504)),
            ("zeros_5504", b"\x00" * 5504),
            ("ones_5504", b"\xff" * 5504),
            ("pattern_aa55_5504", b"\xaa\x55" * 2752),
            ("oversized_10000", os.urandom(10000)),
        ],
    )
    def test_random_bytes_rejected_on_verifier(
        self,
        zkml_verifier: ZKMLVerifier,
        genuine_proof_result: ZKMLProofResult,
        canonical_feature_vector: list[float],
        pattern_name: str,
        byte_payload: bytes,
    ):
        tampered = replace(
            genuine_proof_result,
            proof_bytes=byte_payload,
            hex_proof="0x" + byte_payload.hex(),
        )
        assert zkml_verifier.verify(tampered, feature_vector=canonical_feature_vector) is False

    def test_contract6_random_bytes_in_file_rejected(
        self, zkml_prover: ZKMLProver, genuine_proof_result: ZKMLProofResult, tmp_path: Path
    ):
        proof_file = tmp_path / "random_bytes.json"
        rand_bytes = os.urandom(5504)
        d = dict(genuine_proof_result.raw_proof_dict)
        d["proof"] = list(rand_bytes)
        d["hex_proof"] = "0x" + rand_bytes.hex()
        with open(proof_file, "w", encoding="utf-8") as f:
            json.dump(d, f)

        ok = verify_proof(
            proof_path=proof_file,
            settings_path=zkml_prover.settings_path,
            vk_path=zkml_prover.vk_path,
            srs_path=zkml_prover.srs_path,
        )
        assert ok is False


# ==============================================================================
# Genuine Proof Determinism & Reliability
# ==============================================================================

class TestGenuineProofDeterminism:
    """Tests that authentic proofs verify reliably, deterministically, and with low latency."""

    def test_genuine_proof_deterministic_verification(
        self, zkml_verifier: ZKMLVerifier, genuine_proof_result: ZKMLProofResult, canonical_feature_vector: list[float]
    ):
        for run_idx in range(5):
            ok = zkml_verifier.verify(genuine_proof_result, feature_vector=canonical_feature_vector)
            assert ok is True, f"Genuine proof verification failed on iteration {run_idx}"

    def test_multiple_distinct_feature_vectors(
        self, zkml_prover: ZKMLProver, zkml_verifier: ZKMLVerifier
    ):
        distinct_vectors = [
            [0.5, 0.0, 1.0, 5.0, 5.0, 0.5, 1.0, 0.5, 0.2, 0.4],
            [2.0, 1.0, 4.0, 25.0, 20.0, 0.99, 5.0, 2.0, 0.8, 0.95],
            [0.1, 0.0, 0.0, 1.0, 0.5, 0.1, 0.2, 0.1, 0.05, 0.1],
        ]
        for vec in distinct_vectors:
            proof_res = zkml_prover.prove(vec)
            assert proof_res.is_valid is True
            assert len(proof_res.proof_bytes) == 5504
            assert zkml_verifier.verify(proof_res, feature_vector=vec) is True


# ==============================================================================
# Database Hash Invariance
# ==============================================================================

class TestDatabaseHashInvariance:
    """Verifies that SQLite forensic databases remain 100% bitwise invariant."""

    def test_real_p4_hash_invariant(self):
        p = Path("data/real_p4.db")
        assert p.is_file(), "data/real_p4.db missing"
        sha256 = hashlib.sha256(p.read_bytes()).hexdigest()
        assert sha256 == EXPECTED_REAL_P4_SHA256, (
            f"data/real_p4.db modified! Expected {EXPECTED_REAL_P4_SHA256}, got {sha256}"
        )

    def test_forensics_hash_invariant(self):
        p = Path("data/forensics.db")
        assert p.is_file(), "data/forensics.db missing"
        sha256 = hashlib.sha256(p.read_bytes()).hexdigest()
        assert sha256 == EXPECTED_FORENSICS_SHA256, (
            f"data/forensics.db modified! Expected {EXPECTED_FORENSICS_SHA256}, got {sha256}"
        )
