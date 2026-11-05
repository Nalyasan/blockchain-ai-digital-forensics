"""Comprehensive Adversarial Challenge Suite for Phase 3 (P10) DID, EIP-712, and Custody.

Authored by challenger_M3_2 (Empirical Challenger).
Stress-tests:
1. Invalid DID formats, boundary conditions, homoglyphs, injection attempts.
2. Tampered EIP-712 payloads (field tampering, domain tampering, cross-chain, cross-contract).
3. Wrong signer verification, impersonation, garbage/truncated signatures.
4. Private key canary leaks, sensitive token detection, and zero-leakage guarantees.
5. Deterministic canonical serialization and cryptographic collision/invariance.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import pytest
from pathlib import Path

from forensics.did.resolution import format_did, parse_did, is_valid_did, resolve_did
from forensics.did.eip712 import (
    make_domain,
    build_custody_transfer_typed_data,
    build_attestation_typed_data,
    sign_typed_data,
    verify_typed_signature,
    ROLE_COLLECTOR,
    ROLE_ANALYST,
    ROLE_FIRST_RESPONDER,
    ROLE_ZKML_VERIFIER,
    ROLE_CUSTODIAN,
)
from forensics.did.artifacts import (
    canonical_json_bytes,
    canonical_hash,
    compute_file_sha256,
    create_ml_xai_attestation_payload,
    create_zkml_attestation_payload,
    scan_for_sensitive_leakage,
    CANARY_PATTERNS,
)

# Standard Anvil Accounts & Private Keys for empirical stress testing
ALICE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ALICE_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

BOB_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
BOB_ADDR = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

CHARLIE_KEY = "0x5de4111afa1a4b94908f83103eb2f954b14e043d772c79168c76195a2e139b40"
CHARLIE_ADDR = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"

CONTRACT_ADDR = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
CHAIN_ID = 31337


# ==============================================================================
# 1. DID Format & Resolution Adversarial Tests
# ==============================================================================
class TestDIDAdversarialFormats:
    """Stress tests ERC-1056 DID parsing, formatting, and W3C document resolution."""

    @pytest.mark.parametrize(
        "invalid_input",
        [
            "",
            "   ",
            "\t\n\r",
            None,
            12345,
            0x1234,
            [],
            {},
            b"0x1234",
            "0x123",  # too short
            "0x" + "a" * 39,  # 39 hex chars (19.5 bytes)
            "0x" + "b" * 41,  # 41 hex chars
            "0x" + "c" * 64,  # 32 bytes instead of 20
            "0x" + "z" * 40,  # non-hex character
            "0x" + "g" * 40,  # non-hex character
            "did:ethr:0x" + "a" * 40,  # already formatted as DID
            "123456789012345678901234567890123456789",  # 39 chars without 0x
            "12345678901234567890123456789012345678901",  # 41 chars without 0x
            "０ｘ１２３４５６７８９０１２３４５６７８９０１２３４５６７８９０１２３４５６７８９０",  # Fullwidth
            "0x1234567890123456789012345678901234567890\x00",  # Null byte injection
            "0x1234567890123456789012345678901234567890; DROP TABLE",  # SQL injection
        ],
    )
    def test_format_did_rejects_invalid_address(self, invalid_input):
        with pytest.raises(ValueError):
            format_did(invalid_input)

    @pytest.mark.parametrize(
        "invalid_did",
        [
            "",
            "   ",
            "\n\t",
            "did:",
            "did:ethr",
            "did:ethr:",
            "did:btcr:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",  # wrong method
            "did:ethr:0x123",  # truncated address
            "did:ethr:0x" + "a" * 39,
            "did:ethr:0x" + "a" * 41,
            "did:ethr:0x" + "g" * 40,  # non-hex
            "did:ethr:f39Fd6e51aad88F6F4ce6aB8827279cffFb92266",  # missing 0x in address
            "did:ethr:mainnet:f39Fd6e51aad88F6F4ce6aB8827279cffFb92266",  # missing 0x in address
            "did:ethr:::0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",  # multiple colons
            "did:ethr:../../etc/passwd:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",  # path traversal
            "did:ethr:0x0:0x" + "1" * 40 + "\x00",  # null byte
        ],
    )
    def test_parse_did_rejects_malformed_dids(self, invalid_did):
        assert is_valid_did(invalid_did) is False
        with pytest.raises(ValueError):
            parse_did(invalid_did)
        with pytest.raises(ValueError):
            resolve_did(invalid_did)

    def test_parse_did_boundary_chain_ids(self):
        # Decimal chain ID
        addr = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        did_dec = f"did:ethr:11155111:{addr}"
        parsed_addr, cid = parse_did(did_dec)
        assert parsed_addr == addr
        assert cid == 11155111

        # Hex chain ID
        did_hex = f"did:ethr:0x7a69:{addr}"
        parsed_addr, cid = parse_did(did_hex)
        assert parsed_addr == addr
        assert cid == 31337

        # No network prefix -> chain_id is None
        did_plain = f"did:ethr:{addr}"
        parsed_addr, cid = parse_did(did_plain)
        assert parsed_addr == addr
        assert cid is None

    def test_resolve_did_w3c_strict_compliance(self):
        addr = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        did = f"did:ethr:{addr}"
        doc = resolve_did(did, default_chain_id=1)
        assert doc["id"] == did
        assert doc["@context"][0] == "https://www.w3.org/ns/did/v1"
        assert len(doc["verificationMethod"]) == 1
        vm = doc["verificationMethod"][0]
        assert vm["controller"] == did
        assert vm["blockchainAccountId"] == f"eip155:1:{addr}"
        assert doc["authentication"] == [f"{did}#controller"]
        assert doc["assertionMethod"] == [f"{did}#controller"]


# ==============================================================================
# 2. Tampered EIP-712 Payloads & Schema Integrity Tests
# ==============================================================================
class TestEIP712AdversarialTampering:
    """Stress tests EIP-712 payload tamper detection and domain binding."""

    def test_custody_transfer_signature_tampered_evidence_id(self):
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=CONTRACT_ADDR,
            chain_id=CHAIN_ID,
            evidence_id=1,
            from_custodian=ALICE_ADDR,
            to_custodian=BOB_ADDR,
            artifact_sha256="0x" + "11" * 32,
            note_hash="0x" + "22" * 32,
            nonce=0,
            deadline=1999999999,
        )
        sig = sign_typed_data(typed_data, private_key=ALICE_KEY)

        # Baseline passes
        assert verify_typed_signature(ALICE_ADDR, typed_data, sig) is True

        # Adversarial tamper: Change evidenceId
        tampered_data = json.loads(json.dumps(typed_data))
        tampered_data["message"]["evidenceId"] = 2
        assert verify_typed_signature(ALICE_ADDR, tampered_data, sig) is False

    def test_custody_transfer_signature_tampered_recipient(self):
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=CONTRACT_ADDR,
            chain_id=CHAIN_ID,
            evidence_id=1,
            from_custodian=ALICE_ADDR,
            to_custodian=BOB_ADDR,
            artifact_sha256="0x" + "11" * 32,
            note_hash="0x" + "22" * 32,
            nonce=0,
            deadline=1999999999,
        )
        sig = sign_typed_data(typed_data, private_key=ALICE_KEY)

        # Adversarial tamper: Change recipient from BOB to CHARLIE
        tampered_data = json.loads(json.dumps(typed_data))
        tampered_data["message"]["toCustodian"] = CHARLIE_ADDR.lower()
        assert verify_typed_signature(ALICE_ADDR, tampered_data, sig) is False

    def test_custody_transfer_signature_tampered_artifact_hash(self):
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=CONTRACT_ADDR,
            chain_id=CHAIN_ID,
            evidence_id=1,
            from_custodian=ALICE_ADDR,
            to_custodian=BOB_ADDR,
            artifact_sha256="0x" + "11" * 32,
            note_hash="0x" + "22" * 32,
            nonce=0,
            deadline=1999999999,
        )
        sig = sign_typed_data(typed_data, private_key=ALICE_KEY)

        # Adversarial tamper: Flip 1 byte in artifact hash
        tampered_data = json.loads(json.dumps(typed_data))
        tampered_data["message"]["artifactSha256"] = "0x" + "11" * 31 + "12"
        assert verify_typed_signature(ALICE_ADDR, tampered_data, sig) is False

    def test_custody_transfer_signature_tampered_nonce(self):
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=CONTRACT_ADDR,
            chain_id=CHAIN_ID,
            evidence_id=1,
            from_custodian=ALICE_ADDR,
            to_custodian=BOB_ADDR,
            artifact_sha256="0x" + "11" * 32,
            note_hash="0x" + "22" * 32,
            nonce=0,
            deadline=1999999999,
        )
        sig = sign_typed_data(typed_data, private_key=ALICE_KEY)

        # Adversarial tamper: Change nonce from 0 to 1
        tampered_data = json.loads(json.dumps(typed_data))
        tampered_data["message"]["nonce"] = 1
        assert verify_typed_signature(ALICE_ADDR, tampered_data, sig) is False

    def test_custody_transfer_cross_chain_replay_tamper(self):
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=CONTRACT_ADDR,
            chain_id=CHAIN_ID,  # 31337
            evidence_id=1,
            from_custodian=ALICE_ADDR,
            to_custodian=BOB_ADDR,
            artifact_sha256="0x" + "11" * 32,
            note_hash="0x" + "22" * 32,
            nonce=0,
            deadline=1999999999,
        )
        sig = sign_typed_data(typed_data, private_key=ALICE_KEY)

        # Adversarial replay attack on Ethereum Mainnet (chainId = 1)
        tampered_data = json.loads(json.dumps(typed_data))
        tampered_data["domain"]["chainId"] = 1
        assert verify_typed_signature(ALICE_ADDR, tampered_data, sig) is False

    def test_custody_transfer_cross_contract_replay_tamper(self):
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=CONTRACT_ADDR,
            chain_id=CHAIN_ID,
            evidence_id=1,
            from_custodian=ALICE_ADDR,
            to_custodian=BOB_ADDR,
            artifact_sha256="0x" + "11" * 32,
            note_hash="0x" + "22" * 32,
            nonce=0,
            deadline=1999999999,
        )
        sig = sign_typed_data(typed_data, private_key=ALICE_KEY)

        # Adversarial replay attack against different contract address
        tampered_data = json.loads(json.dumps(typed_data))
        tampered_data["domain"]["verifyingContract"] = BOB_ADDR.lower()
        assert verify_typed_signature(ALICE_ADDR, tampered_data, sig) is False

    def test_attestation_signature_tampered_role(self):
        typed_data = build_attestation_typed_data(
            verifying_contract=CONTRACT_ADDR,
            chain_id=CHAIN_ID,
            evidence_id=10,
            attestor=ALICE_ADDR,
            role=ROLE_ANALYST,
            artifact_hash="0x" + "33" * 32,
            statement_hash="0x" + "44" * 32,
            nonce=0,
            deadline=1999999999,
        )
        sig = sign_typed_data(typed_data, private_key=ALICE_KEY)

        # Baseline passes
        assert verify_typed_signature(ALICE_ADDR, typed_data, sig) is True

        # Adversarial tamper: Elevate/change role to ROLE_ZKML_VERIFIER
        tampered_data = json.loads(json.dumps(typed_data))
        tampered_data["message"]["role"] = ROLE_ZKML_VERIFIER
        assert verify_typed_signature(ALICE_ADDR, tampered_data, sig) is False

    @pytest.mark.parametrize(
        "invalid_field,value",
        [
            ("artifact_sha256", "0x123"),  # short bytes32
            ("artifact_sha256", "0x" + "1" * 63),
            ("artifact_sha256", "0x" + "1" * 65),
            ("artifact_sha256", "not_hex"),
            ("from_custodian", "0x123"),  # short address
            ("from_custodian", "0x" + "a" * 41),
            ("to_custodian", "0x" + "g" * 40),  # non-hex address
            ("note_hash", "0x" + "f" * 66),  # too long
        ],
    )
    def test_build_typed_data_rejects_malformed_fields(self, invalid_field, value):
        kwargs = {
            "verifying_contract": CONTRACT_ADDR,
            "chain_id": CHAIN_ID,
            "evidence_id": 1,
            "from_custodian": ALICE_ADDR,
            "to_custodian": BOB_ADDR,
            "artifact_sha256": "0x" + "11" * 32,
            "note_hash": "0x" + "22" * 32,
            "nonce": 0,
            "deadline": 1999999999,
        }
        kwargs[invalid_field] = value
        with pytest.raises(ValueError):
            build_custody_transfer_typed_data(**kwargs)


# ==============================================================================
# 3. Signer Verification, Impersonation & Malformed Signature Tests
# ==============================================================================
class TestSignerVerificationAdversarial:
    """Stress tests ECDSA recovery against impersonation, wrong keys, and invalid signature bytes."""

    def test_signature_signed_by_alice_rejected_for_bob(self):
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=CONTRACT_ADDR,
            chain_id=CHAIN_ID,
            evidence_id=1,
            from_custodian=ALICE_ADDR,
            to_custodian=BOB_ADDR,
            artifact_sha256="0x" + "aa" * 32,
            note_hash="0x" + "bb" * 32,
            nonce=0,
            deadline=1999999999,
        )
        sig = sign_typed_data(typed_data, private_key=ALICE_KEY)

        # Alice is the real signer
        assert verify_typed_signature(ALICE_ADDR, typed_data, sig) is True

        # Impersonation attempt: Claim Bob signed Alice's authorization
        assert verify_typed_signature(BOB_ADDR, typed_data, sig) is False
        assert verify_typed_signature(CHARLIE_ADDR, typed_data, sig) is False

    def test_signature_signed_by_bob_rejected_for_alice(self):
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=CONTRACT_ADDR,
            chain_id=CHAIN_ID,
            evidence_id=1,
            from_custodian=ALICE_ADDR,
            to_custodian=BOB_ADDR,
            artifact_sha256="0x" + "aa" * 32,
            note_hash="0x" + "bb" * 32,
            nonce=0,
            deadline=1999999999,
        )
        # Attacker Bob attempts to forge Alice's transfer by signing with his own key
        sig = sign_typed_data(typed_data, private_key=BOB_KEY)

        # Verification must reject when checking against Alice's address
        assert verify_typed_signature(ALICE_ADDR, typed_data, sig) is False
        # But verifies that Bob was indeed the rogue signer
        assert verify_typed_signature(BOB_ADDR, typed_data, sig) is True

    @pytest.mark.parametrize(
        "garbage_sig",
        [
            "0x" + "00" * 65,  # All zeroes (v=0, invalid)
            "0x" + "ff" * 65,  # All 0xff
            "0x" + "12" * 32,  # Truncated (32 bytes)
            "0x" + "12" * 64,  # Truncated (64 bytes, missing v)
            "0x" + "12" * 66,  # Oversized (66 bytes)
            "0x1234",          # Arbitrary short hex
            "not_a_hex_signature",
            "",
        ],
    )
    def test_verify_typed_signature_rejects_garbage_signatures(self, garbage_sig):
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=CONTRACT_ADDR,
            chain_id=CHAIN_ID,
            evidence_id=1,
            from_custodian=ALICE_ADDR,
            to_custodian=BOB_ADDR,
            artifact_sha256="0x" + "aa" * 32,
            note_hash="0x" + "bb" * 32,
            nonce=0,
            deadline=1999999999,
        )
        assert verify_typed_signature(ALICE_ADDR, typed_data, garbage_sig) is False

    def test_sign_typed_data_requires_auth(self):
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=CONTRACT_ADDR,
            chain_id=CHAIN_ID,
            evidence_id=1,
            from_custodian=ALICE_ADDR,
            to_custodian=BOB_ADDR,
            artifact_sha256="0x" + "aa" * 32,
            note_hash="0x" + "bb" * 32,
            nonce=0,
            deadline=1999999999,
        )
        with pytest.raises(ValueError, match="AUTH_REQUIRED"):
            sign_typed_data(typed_data, private_key=None, account=None)


# ==============================================================================
# 4. Canary Leakage Detection & ISO/IEC 27037 Zero-Leakage Guarantees
# ==============================================================================
class TestCanaryLeaksAndZeroLeakage:
    """Stress tests canary detection and confirms that on-chain payloads leak no secrets."""

    def test_scan_for_sensitive_leakage_matches_canary_list(self):
        payload = {
            "entity": "0x1234567890123456789012345678901234567890",
            "leak": "SECRET_CANARY_ALPHA_99",
            "safe_metric": 42.0,
        }
        canaries = ["SECRET_CANARY_ALPHA_99", "SECRET_CANARY_BETA_88"]
        detected = scan_for_sensitive_leakage(payload, canaries=canaries)
        assert detected == ["SECRET_CANARY_ALPHA_99"]

    def test_canary_regex_patterns_detect_private_keys_and_tokens(self):
        test_strings = [
            ("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", True),  # Private key
            ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", True),  # Bearer token
            ("api_key = abcdef1234567890", True),  # API key
            ("password: supersecretpassword123", True),  # Password
            ("0x1234567890123456789012345678901234567890", False),  # 20-byte address (benign)
            ("This is a benign forensic summary report.", False),  # Normal text
        ]
        for text, should_match in test_strings:
            matched = any(pattern.search(text) for pattern in CANARY_PATTERNS)
            assert matched == should_match, f"Failed pattern check for: {text}"

    def test_ml_xai_attestation_payload_never_leaks_nested_canaries(self):
        # Construct an explanation dict contaminated with secrets and canaries
        secret_canary = "CANARY_PRIVATE_LEAK_TEST_99"
        raw_private_key = ALICE_KEY
        contaminated_explanation = {
            "model_version": "v1.0.0",
            "top_drivers": ["feature_burst", "feature_fanout"],
            "shapley_values": [0.45, 0.32, -0.11],
            "leaked_key": raw_private_key,
            "secret_canary": secret_canary,
            "raw_weights": [0.1234, 0.5678, 0.9999] * 100,
        }

        model_hash = "0x" + hashlib.sha256(b"dummy_model_onnx_bytes").hexdigest()
        art_hash, stmt_hash = create_ml_xai_attestation_payload(
            evidence_id=42,
            model_sha256=model_hash,
            entity_address=ALICE_ADDR,
            explanation_dict=contaminated_explanation,
        )

        # 1. Output hashes must be exact 32-byte hex strings
        assert len(art_hash) == 66 and art_hash.startswith("0x")
        assert len(stmt_hash) == 66 and stmt_hash.startswith("0x")

        # 2. Assert neither hash contains any canary or secret substring
        assert secret_canary not in art_hash
        assert secret_canary not in stmt_hash
        assert raw_private_key[2:] not in art_hash
        assert raw_private_key[2:] not in stmt_hash

        # 3. Scanning the hashes themselves reveals zero leaks
        assert scan_for_sensitive_leakage(art_hash, canaries=[secret_canary, raw_private_key]) == []
        assert scan_for_sensitive_leakage(stmt_hash, canaries=[secret_canary, raw_private_key]) == []

    def test_zkml_attestation_payload_never_leaks_proof_witness_or_canaries(self):
        secret_canary = "CANARY_ZK_WITNESS_SECRET"
        raw_proof_pi = b"halo2_circuit_proof_bytes_with_private_witness" + secret_canary.encode()
        proof_hash = "0x" + hashlib.sha256(raw_proof_pi).hexdigest()
        model_hash = "0x" + hashlib.sha256(b"mlp_anomaly_model").hexdigest()
        vk_hash = "0x" + hashlib.sha256(b"verification_key_bytes").hexdigest()

        art_hash, stmt_hash = create_zkml_attestation_payload(
            evidence_id=77,
            model_sha256=model_hash,
            proof_sha256=proof_hash,
            input_commitment="0x" + "55" * 32,
            output_commitment="0x" + "66" * 32,
            vk_sha256=vk_hash,
        )

        assert len(art_hash) == 66
        assert len(stmt_hash) == 66
        assert secret_canary not in art_hash
        assert secret_canary not in stmt_hash


# ==============================================================================
# 5. Determinism & Cryptographic Invariance
# ==============================================================================
class TestCryptographicInvariance:
    """Stress tests canonical serialization, key order invariance, and hash collisions."""

    def test_canonical_json_bytes_key_order_invariance(self):
        d1 = {"z": 100, "a": 1, "m": {"inner_b": 2, "inner_a": 1}}
        d2 = {"a": 1, "m": {"inner_a": 1, "inner_b": 2}, "z": 100}

        b1 = canonical_json_bytes(d1)
        b2 = canonical_json_bytes(d2)

        # Must produce 100% byte-for-byte identical output
        assert b1 == b2
        assert b" " not in b1  # No whitespace separators
        assert canonical_hash(d1) == canonical_hash(d2)

    def test_compute_file_sha256_non_existent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            compute_file_sha256(Path(__file__).parent / "non_existent_file_12345.xyz")
