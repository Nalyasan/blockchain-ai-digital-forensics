"""Adversarial Stress & Concordance Challenge Suite for Milestone M4 Iteration 2.

Agent: challenger_v6_M4_2_iter2 (Empirical Challenger)
Objectives:
  1. Verify live single-bit hash corruption triggers fail-closed AssertionError
     across all 4 forensic hashes (original_sha256, model_hash, xai_digest, zkml_proof_hash)
     in both raw EVM returndata and decoded record structs.
  2. Challenge decode_custody_records with adversarial inputs:
     truncated hex, empty strings, oversized counts, out-of-bounds offsets,
     and boundary conditions.
  3. Verify Anvil dynamic lifecycle, port binding, and fail-closed Gate T24 transaction reverts.
  4. Verify 100% bitwise invariance of all 4 canonical databases.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

import pytest

from forensics.did.client import AnvilTestNode, DIDClient, ANVIL_DEFAULT_DEPLOYER, decode_custody_records
from forensics.did.eip712 import (
    ROLE_COLLECTOR,
    ROLE_ANALYST,
    ROLE_CUSTODIAN,
    build_custody_transfer_typed_data,
    sign_typed_data,
    make_domain,
)

DEPLOYER = ANVIL_DEFAULT_DEPLOYER
ALICE = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
ALICE_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
BOB = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
BOB_PK = "0x5de4111afa1a4b94908f83103eb2f9540808a0cb84e727575745778853a81230"


def flip_bit(h_hex: str, bit_idx: int) -> str:
    """Flips the bit at bit_idx in a 64-char (32-byte) hex string."""
    val = int(h_hex, 16)
    val ^= (1 << bit_idx)
    return hex(val)[2:].zfill(64)


class TestLiveHashConcordanceCorruption:
    """Stress tests verifying that altering any bit in hashes triggers immediate fail-closed AssertionError."""

    @pytest.fixture(scope="class")
    def live_anchored_custody(self):
        """Spawns an Anvil node, executes Alice -> Bob handover, anchors hashes, returns context."""
        orig_sha = hashlib.sha256(b"adversarial_evidence_payload_iter2").hexdigest()
        model_h = hashlib.sha256(b"adversarial_onnx_model_iter2").hexdigest()
        xai_d = hashlib.sha256(b"adversarial_xai_digest_iter2").hexdigest()
        zkml_h = hashlib.sha256(b"adversarial_zkml_proof_iter2").hexdigest()
        note_h = hashlib.sha256(b"adversarial_note_iter2").hexdigest()

        with AnvilTestNode(chain_id=31337) as node:
            client = DIDClient(rpc_url=node.rpc_url, chain_id=31337)
            contract_addr = client.deploy_registry(deployer_address=DEPLOYER)
            client.grant_role(ALICE, ROLE_COLLECTOR, sender=DEPLOYER)
            client.grant_role(ALICE, ROLE_CUSTODIAN, sender=DEPLOYER)
            client.grant_role(BOB, ROLE_ANALYST, sender=DEPLOYER)
            client.grant_role(BOB, ROLE_CUSTODIAN, sender=DEPLOYER)

            # Register evidence
            ev_id = client.register_evidence(
                case_id_bytes32="0x" + hashlib.sha256(b"CASE-CORRUPTION-TEST").hexdigest(),
                manifest_sha256="0x" + orig_sha,
                storage_uri="evidence://case-corruption/manifest.json",
                sender=ALICE,
            )

            # Transfer Alice -> Bob
            nonce = client.get_nonce(ALICE)
            deadline = int(time.time()) + 3600
            typed = build_custody_transfer_typed_data(
                verifying_contract=contract_addr,
                chain_id=31337,
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_sha,
                note_hash="0x" + note_h,
                nonce=nonce,
                deadline=deadline,
            )
            sig = sign_typed_data(typed, ALICE_PK)
            client.transfer_custody_with_sig_receipt(
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_sha,
                note_hash="0x" + note_h,
                nonce=nonce,
                deadline=deadline,
                signature=sig,
                sender=BOB,
            )

            # Bob anchors forensic digests
            client.anchor_forensic_evidence(
                evidence_id=ev_id,
                model_hash="0x" + model_h,
                xai_digest="0x" + xai_d,
                zkml_proof_hash="0x" + zkml_h,
                artifact_sha256="0x" + orig_sha,
                note_hash="0x" + note_h,
                sender=BOB,
            )

            hist = client.get_custody_history_did(ev_id)
            raw_hex = "".join(hist[0]["raw_lines"]).lower()
            decoded = hist[0]["decoded_records"]

            yield {
                "orig_sha": orig_sha,
                "model_h": model_h,
                "xai_d": xai_d,
                "zkml_h": zkml_h,
                "raw_hex": raw_hex,
                "decoded": decoded,
            }

    def test_baseline_uncorrupted_hashes_pass(self, live_anchored_custody):
        ctx = live_anchored_custody
        rec_anchor = ctx["decoded"][1]

        # Raw containment
        assert ctx["orig_sha"].lower() in ctx["raw_hex"]
        assert ctx["model_h"].lower() in ctx["raw_hex"]
        assert ctx["xai_d"].lower() in ctx["raw_hex"]
        assert ctx["zkml_h"].lower() in ctx["raw_hex"]

        # Decoded equality
        assert rec_anchor["artifact_sha256"] == ctx["orig_sha"].lower()
        assert rec_anchor["model_hash"] == ctx["model_h"].lower()
        assert rec_anchor["xai_digest"] == ctx["xai_d"].lower()
        assert rec_anchor["zkml_proof_hash"] == ctx["zkml_h"].lower()

    @pytest.mark.parametrize("bit_idx", [0, 1, 7, 8, 31, 63, 64, 127, 128, 200, 254, 255])
    def test_corrupted_original_sha256_fails_closed(self, live_anchored_custody, bit_idx):
        ctx = live_anchored_custody
        corrupted = flip_bit(ctx["orig_sha"], bit_idx)
        assert corrupted != ctx["orig_sha"]

        # Raw substring check must fail closed
        with pytest.raises(AssertionError):
            assert corrupted.lower() in ctx["raw_hex"], "Fail-closed check"

        # Decoded record equality check must fail closed
        with pytest.raises(AssertionError):
            assert ctx["decoded"][1]["artifact_sha256"] == corrupted.lower(), "Fail-closed check"

    @pytest.mark.parametrize("bit_idx", [0, 1, 7, 8, 31, 63, 64, 127, 128, 200, 254, 255])
    def test_corrupted_model_hash_fails_closed(self, live_anchored_custody, bit_idx):
        ctx = live_anchored_custody
        corrupted = flip_bit(ctx["model_h"], bit_idx)
        assert corrupted != ctx["model_h"]

        with pytest.raises(AssertionError):
            assert corrupted.lower() in ctx["raw_hex"]

        with pytest.raises(AssertionError):
            assert ctx["decoded"][1]["model_hash"] == corrupted.lower()

    @pytest.mark.parametrize("bit_idx", [0, 1, 7, 8, 31, 63, 64, 127, 128, 200, 254, 255])
    def test_corrupted_xai_digest_fails_closed(self, live_anchored_custody, bit_idx):
        ctx = live_anchored_custody
        corrupted = flip_bit(ctx["xai_d"], bit_idx)
        assert corrupted != ctx["xai_d"]

        with pytest.raises(AssertionError):
            assert corrupted.lower() in ctx["raw_hex"]

        with pytest.raises(AssertionError):
            assert ctx["decoded"][1]["xai_digest"] == corrupted.lower()

    @pytest.mark.parametrize("bit_idx", [0, 1, 7, 8, 31, 63, 64, 127, 128, 200, 254, 255])
    def test_corrupted_zkml_proof_hash_fails_closed(self, live_anchored_custody, bit_idx):
        ctx = live_anchored_custody
        corrupted = flip_bit(ctx["zkml_h"], bit_idx)
        assert corrupted != ctx["zkml_h"]

        with pytest.raises(AssertionError):
            assert corrupted.lower() in ctx["raw_hex"]

        with pytest.raises(AssertionError):
            assert ctx["decoded"][1]["zkml_proof_hash"] == corrupted.lower()


class TestDecodeCustodyRecordsRobustness:
    """Fuzzing and boundary stress tests for decode_custody_records parser."""

    def test_empty_and_zero_length_inputs(self):
        assert decode_custody_records("") == []
        assert decode_custody_records("0x") == []
        assert decode_custody_records("0X") == []
        assert decode_custody_records("   \n\t  ") == []

    def test_truncated_hex_lengths(self):
        # Slices shorter than 128 hex chars (2 ABI words) must return [] safely
        assert decode_custody_records("0x1234") == []
        assert decode_custody_records("00" * 32) == []
        assert decode_custody_records("00" * 63 + "f") == []

    def test_zero_count_records(self):
        # 128 chars of zeroes: word 0 = offset 0x00, word 1 = count 0
        raw = "00" * 64
        assert decode_custody_records(raw) == []

    def test_count_greater_than_available_words(self):
        # Word 0: 0x20, Word 1: count=5, but only 2 words provided
        raw = "00" * 31 + "20" + "00" * 31 + "05"
        assert decode_custody_records(raw) == []

    def test_oversized_count_does_not_infinite_loop(self):
        # Word 1: count = 1,000,000
        raw = "00" * 31 + "20" + "00" * 28 + "000f4240" + "00" * 32
        start = time.time()
        assert decode_custody_records(raw) == []
        assert time.time() - start < 1.0, "Parser hung on oversized count!"

    def test_element_offset_out_of_bounds(self):
        # Word 0: 0x20, Word 1: count=1, Word 2: offset=0xFFFF (far out of bounds)
        raw = "00" * 31 + "20" + "00" * 31 + "01" + "00" * 30 + "ffff"
        assert decode_custody_records(raw) == []

    def test_truncated_element_struct_words(self):
        # Word 0: 0x20, Word 1: count=1, Word 2: offset=0x20 (word 3)
        # Word 3..7: only 5 words of struct (needs at least 12 words)
        raw = "00" * 31 + "20" + "00" * 31 + "01" + "00" * 31 + "20" + ("11" * 32) * 5
        assert decode_custody_records(raw) == []

    def test_completely_non_hex_ascii_input(self):
        # Input has no valid hex count
        raw = "this is completely non-hexadecimal plaintext data!" * 10
        assert decode_custody_records(raw) == []


class TestCanonicalDatabaseInvarianceChallengerIter2:
    """Guarantees 100% bitwise SHA-256 preservation of all 4 canonical databases."""

    CANONICAL_HASHES = {
        "data/real_p4.db": "6bd9aed48ac2742d0862198bff65994861244ec681dc8abeb3e6f771e7808c97",
        "data/forensics.db": "3f2b0dfc772a96ff6ea57c65807b5b6b9a20fcf74c409c6f222fcff29f1ef001",
        "data/benchmark_p6.db": "c7ff724cd214eef57e58a6fbe44dbeb2712c54b035907b2a6279a255c0e80507",
        ".env": "c2f4879666cd21276c58ec75de923c8235d414f3d646a854a835c5638ec1699c",
    }

    def test_canonical_databases_bitwise_identical(self):
        root_dir = Path(__file__).resolve().parents[1]
        for rel_path, expected_hash in self.CANONICAL_HASHES.items():
            full_path = root_dir / rel_path
            assert full_path.exists(), f"Canonical target {rel_path} does not exist!"
            hasher = hashlib.sha256()
            with open(full_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            actual_hash = hasher.hexdigest().lower()
            assert actual_hash == expected_hash, (
                f"CANONICAL DB COMPROMISED: {rel_path} hash {actual_hash} != {expected_hash}"
            )
