"""Unit & Integration Test Suite for Phase 3 / P10 DID & Chain of Custody (ISO/IEC 27037).

Covers:
1. ERC-1056 DID Formatting, Parsing, and W3C DID Core 1.0 Document Resolution
2. EIP-712 Structured Data Schemas (CustodyTransfer & ForensicAttestation)
3. Native Foundry cast.exe Signing and Signature Verification
4. ISO/IEC 27037 Forensic Artifact Anchoring (P8 ML, XAI, and P9 ZKML)
5. Zero-Leakage & Canary Privacy Verification
6. High-level DIDClient (Mock Mode & Ephemeral Anvil Integration)
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
import pytest

from forensics.did.resolution import (
    format_did,
    parse_did,
    resolve_did,
    is_valid_did,
)
from forensics.did.eip712 import (
    EIP712_TYPES,
    ROLE_COLLECTOR,
    ROLE_ANALYST,
    ROLE_FIRST_RESPONDER,
    ROLE_ZKML_VERIFIER,
    ROLE_CUSTODIAN,
    make_domain,
    build_custody_transfer_typed_data,
    build_attestation_typed_data,
    sign_typed_data,
    verify_typed_signature,
)
from forensics.did.artifacts import (
    canonical_hash,
    compute_file_sha256,
    create_ml_xai_attestation_payload,
    create_zkml_attestation_payload,
    scan_for_sensitive_leakage,
)
from forensics.did.client import (
    DIDClient,
    AnvilTestNode,
    ANVIL_DEFAULT_DEPLOYER,
)

# Anvil pre-funded default test account #0
ANVIL_TEST_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_TEST_ADDR = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"

# Anvil pre-funded test account #1
ANVIL_TEST_ADDR_1 = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"


# ==============================================================================
# 1. ERC-1056 DID Formatting, Parsing, & W3C DID Resolution
# ==============================================================================

class TestDIDResolution:
    """Verifies compliance with ERC-1056 and W3C DID Core 1.0 specifications."""

    def test_format_did_canonical(self):
        addr = "0xF39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        did = format_did(addr)
        assert did == "did:ethr:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        assert len(did) == 51

    def test_format_did_network_scoped(self):
        addr = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        did_sepolia = format_did(addr, chain_id=11155111)
        assert did_sepolia == "did:ethr:0xaa36a7:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"

        did_mainnet = format_did(addr, chain_id=1)
        assert did_mainnet == "did:ethr:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"

    def test_format_did_invalid_address_raises(self):
        with pytest.raises(ValueError, match="INVALID_ADDRESS"):
            format_did("0x1234")

        with pytest.raises(ValueError, match="INVALID_ADDRESS"):
            format_did(12345)  # type: ignore

        with pytest.raises(ValueError, match="INVALID_ADDRESS"):
            format_did("not_an_address")

    def test_parse_did_valid(self):
        addr, chain_id = parse_did("did:ethr:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
        assert addr == "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        assert chain_id is None

        addr, chain_id = parse_did("did:ethr:0xaa36a7:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
        assert addr == "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        assert chain_id == 11155111

    def test_parse_did_invalid_raises(self):
        with pytest.raises(ValueError, match="INVALID_DID"):
            parse_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")

        with pytest.raises(ValueError, match="INVALID_DID"):
            parse_did("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")

        with pytest.raises(ValueError, match="INVALID_DID"):
            parse_did(None)  # type: ignore

    def test_is_valid_did(self):
        assert is_valid_did("did:ethr:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
        assert is_valid_did("did:ethr:0xaa36a7:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
        assert not is_valid_did("did:btc:0x123")
        assert not is_valid_did("")
        assert not is_valid_did(12345)  # type: ignore

    def test_resolve_did_w3c_core_1_0(self):
        did = "did:ethr:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        doc = resolve_did(did, default_chain_id=31337)

        assert doc["id"] == did
        assert "@context" in doc
        assert "verificationMethod" in doc
        vm = doc["verificationMethod"][0]
        assert vm["id"] == f"{did}#controller"
        assert vm["type"] == "EcdsaSecp256k1RecoveryMethod2020"
        assert vm["controller"] == did
        assert vm["blockchainAccountId"] == "eip155:31337:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        assert doc["authentication"] == [f"{did}#controller"]
        assert doc["assertionMethod"] == [f"{did}#controller"]


# ==============================================================================
# 2. EIP-712 Structured Data Schemas & Validation
# ==============================================================================

class TestEIP712Schemas:
    """Verifies typed data construction, domain separator, and input sanitization."""

    def test_make_domain(self):
        contract = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        dom = make_domain(contract, chain_id=31337)
        assert dom["name"] == "EvidenceRegistryDID"
        assert dom["version"] == "1"
        assert dom["chainId"] == 31337
        assert dom["verifyingContract"] == contract.lower()

    def test_build_custody_transfer_typed_data(self):
        contract = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        art_hash = "0x" + "aa" * 32
        note_h = "0x" + "bb" * 32

        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=1,
            from_custodian=ANVIL_TEST_ADDR,
            to_custodian=ANVIL_TEST_ADDR_1,
            artifact_sha256=art_hash,
            note_hash=note_h,
            nonce=0,
            deadline=1800000000,
        )

        assert typed_data["primaryType"] == "CustodyTransfer"
        assert "EIP712Domain" in typed_data["types"]
        assert "CustodyTransfer" in typed_data["types"]
        msg = typed_data["message"]
        assert msg["evidenceId"] == 1
        assert msg["fromCustodian"] == ANVIL_TEST_ADDR.lower()
        assert msg["toCustodian"] == ANVIL_TEST_ADDR_1.lower()
        assert msg["artifactSha256"] == art_hash.lower()
        assert msg["noteHash"] == note_h.lower()
        assert msg["nonce"] == 0
        assert msg["deadline"] == 1800000000

    def test_build_attestation_typed_data(self):
        contract = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        art_hash = "0x" + "11" * 32
        stmt_hash = "0x" + "22" * 32

        typed_data = build_attestation_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=42,
            attestor=ANVIL_TEST_ADDR,
            role=ROLE_ANALYST,
            artifact_hash=art_hash,
            statement_hash=stmt_hash,
            nonce=3,
            deadline=1900000000,
        )

        assert typed_data["primaryType"] == "ForensicAttestation"
        msg = typed_data["message"]
        assert msg["evidenceId"] == 42
        assert msg["attestor"] == ANVIL_TEST_ADDR.lower()
        assert msg["role"] == ROLE_ANALYST.lower()
        assert msg["artifactHash"] == art_hash.lower()
        assert msg["statementHash"] == stmt_hash.lower()
        assert msg["nonce"] == 3
        assert msg["deadline"] == 1900000000

    def test_invalid_bytes32_rejected(self):
        contract = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        with pytest.raises(ValueError, match="INVALID_BYTES32"):
            build_custody_transfer_typed_data(
                verifying_contract=contract,
                chain_id=31337,
                evidence_id=1,
                from_custodian=ANVIL_TEST_ADDR,
                to_custodian=ANVIL_TEST_ADDR_1,
                artifact_sha256="0x123",  # Invalid length
                note_hash="0x" + "bb" * 32,
                nonce=0,
                deadline=1800000000,
            )

    def test_invalid_address_rejected(self):
        contract = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        with pytest.raises(ValueError, match="INVALID_ADDRESS"):
            build_custody_transfer_typed_data(
                verifying_contract="not_an_address",
                chain_id=31337,
                evidence_id=1,
                from_custodian=ANVIL_TEST_ADDR,
                to_custodian=ANVIL_TEST_ADDR_1,
                artifact_sha256="0x" + "aa" * 32,
                note_hash="0x" + "bb" * 32,
                nonce=0,
                deadline=1800000000,
            )


# ==============================================================================
# 3. Native Cast EIP-712 Signing & Verification
# ==============================================================================

class TestCastSigningAndVerification:
    """Verifies typed data signing and signature verification using bundled cast.exe."""

    def test_sign_and_verify_valid_signature(self):
        contract = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=1,
            from_custodian=ANVIL_TEST_ADDR,
            to_custodian=ANVIL_TEST_ADDR_1,
            artifact_sha256="0x" + "aa" * 32,
            note_hash="0x" + "bb" * 32,
            nonce=0,
            deadline=1800000000,
        )

        # Sign using cast wallet sign
        sig = sign_typed_data(typed_data, private_key=ANVIL_TEST_PK)
        assert sig.startswith("0x")
        assert len(sig) == 132  # 65 bytes hex (0x + 130 chars)

        # Verify using cast wallet verify
        valid = verify_typed_signature(ANVIL_TEST_ADDR, typed_data, sig)
        assert valid is True

    def test_verify_rejects_wrong_signer_address(self):
        contract = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=1,
            from_custodian=ANVIL_TEST_ADDR,
            to_custodian=ANVIL_TEST_ADDR_1,
            artifact_sha256="0x" + "aa" * 32,
            note_hash="0x" + "bb" * 32,
            nonce=0,
            deadline=1800000000,
        )

        sig = sign_typed_data(typed_data, private_key=ANVIL_TEST_PK)

        # Assert verification fails when checked against Bob's address
        valid = verify_typed_signature(ANVIL_TEST_ADDR_1, typed_data, sig)
        assert valid is False

    def test_verify_rejects_tampered_payload(self):
        contract = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=1,
            from_custodian=ANVIL_TEST_ADDR,
            to_custodian=ANVIL_TEST_ADDR_1,
            artifact_sha256="0x" + "aa" * 32,
            note_hash="0x" + "bb" * 32,
            nonce=0,
            deadline=1800000000,
        )

        sig = sign_typed_data(typed_data, private_key=ANVIL_TEST_PK)

        # Tamper payload
        tampered = json.loads(json.dumps(typed_data))
        tampered["message"]["evidenceId"] = 999

        valid = verify_typed_signature(ANVIL_TEST_ADDR, tampered, sig)
        assert valid is False


# ==============================================================================
# 4. ISO/IEC 27037 Artifact Anchoring & Zero-Leakage Privacy
# ==============================================================================

class TestArtifactAnchoringAndZeroLeakage:
    """Verifies cryptographic anchoring of P8 ML, XAI, and P9 ZKML digests with zero leakage."""

    def test_canonical_hash_deterministic(self):
        d1 = {"b": 2, "a": 1, "nested": {"y": "hello", "x": [1, 2, 3]}}
        d2 = {"nested": {"x": [1, 2, 3], "y": "hello"}, "a": 1, "b": 2}
        assert canonical_hash(d1) == canonical_hash(d2)

    def test_create_ml_xai_attestation_payload(self):
        model_hash = "0x" + "11" * 32
        entity_addr = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        explanation = {
            "prediction_score": 0.88,
            "baseline_value": 0.12,
            "top_drivers": ["feature_burst", "feature_fan_out"],
        }

        art_hash, stmt_hash = create_ml_xai_attestation_payload(
            evidence_id=1,
            model_sha256=model_hash,
            entity_address=entity_addr,
            explanation_dict=explanation,
        )

        assert art_hash == model_hash.lower()
        assert stmt_hash.startswith("0x")
        assert len(stmt_hash) == 66

    def test_create_zkml_attestation_payload(self):
        model_hash = "0x" + "11" * 32
        proof_hash = "0x" + "22" * 32
        vk_hash = "0x" + "33" * 32

        art_hash, stmt_hash = create_zkml_attestation_payload(
            evidence_id=1,
            model_sha256=model_hash,
            proof_sha256=proof_hash,
            input_commitment="0x" + "44" * 32,
            output_commitment="0x" + "55" * 32,
            vk_sha256=vk_hash,
        )

        assert art_hash == proof_hash.lower()
        assert stmt_hash.startswith("0x")
        assert len(stmt_hash) == 66

    def test_compute_file_sha256(self, tmp_path):
        test_file = tmp_path / "model.onnx"
        test_file.write_bytes(b"dummy ONNX model binary content for testing")
        expected = "0x" + hashlib.sha256(b"dummy ONNX model binary content for testing").hexdigest().lower()
        assert compute_file_sha256(test_file) == expected

    def test_zero_leakage_canary_protection(self):
        canaries = [
            "CANARY_PRIVATE_KEY_0x998877665544332211",
            "CANARY_SECRET_API_TOKEN_xyz123",
            "CONFIDENTIAL_SUSPECT_NAME_JOHN_DOE",
        ]

        # Generate benign attestation payload
        art_hash, stmt_hash = create_ml_xai_attestation_payload(
            evidence_id=10,
            model_sha256="0x" + "11" * 32,
            entity_address=ANVIL_TEST_ADDR,
            explanation_dict={"score": 0.95},
        )

        # Verify no canary appears in hashes
        detected = scan_for_sensitive_leakage(
            {"artifactHash": art_hash, "statementHash": stmt_hash},
            canaries=canaries,
        )
        assert len(detected) == 0


# ==============================================================================
# 5. High-Level DIDClient (Mock Mode & Live Anvil Context Manager)
# ==============================================================================

class TestDIDClient:
    """Verifies DIDClient operations in mock mode and end-to-end against ephemeral Anvil."""

    def test_did_client_mock_mode(self):
        client = DIDClient(mock_mode=True)
        addr = client.deploy_registry()
        assert addr.startswith("0x")

        did = client.get_did(ANVIL_TEST_ADDR)
        assert did == f"did:ethr:{ANVIL_TEST_ADDR.lower()}"

        assert client.get_nonce(ANVIL_TEST_ADDR) == 0

        # Test role granting in mock mode
        client.grant_role(ANVIL_TEST_ADDR, ROLE_COLLECTOR)
        assert client.has_role(ANVIL_TEST_ADDR, ROLE_COLLECTOR) is True

        client.revoke_role(ANVIL_TEST_ADDR, ROLE_COLLECTOR)
        assert client.has_role(ANVIL_TEST_ADDR, ROLE_COLLECTOR) is False

        # Test transfer custody submission
        tx = client.transfer_custody_with_sig(
            evidence_id=1,
            from_custodian=ANVIL_TEST_ADDR,
            to_custodian=ANVIL_TEST_ADDR_1,
            artifact_sha256="0x" + "aa" * 32,
            note_hash="0x" + "bb" * 32,
            nonce=0,
            deadline=1800000000,
            signature="0x" + "11" * 65,
        )
        assert tx.startswith("0x")
        assert client.get_nonce(ANVIL_TEST_ADDR) == 1

    def test_did_client_role_constants_match_contract(self):
        """Verifies Python keccak256 role constants match Solidity contract role definitions."""
        import subprocess
        root_dir = Path(__file__).resolve().parents[1]
        cast_bin = root_dir / "tools" / "foundry" / "cast.exe"

        for role_name, expected_hash in [
            ("ROLE_COLLECTOR", ROLE_COLLECTOR),
            ("ROLE_ANALYST", ROLE_ANALYST),
            ("ROLE_FIRST_RESPONDER", ROLE_FIRST_RESPONDER),
            ("ROLE_ZKML_VERIFIER", ROLE_ZKML_VERIFIER),
            ("ROLE_CUSTODIAN", ROLE_CUSTODIAN),
        ]:
            cmd = [str(cast_bin), "keccak", role_name]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            calculated = res.stdout.strip().lower()
            assert calculated == expected_hash.lower(), f"Mismatch for {role_name}"

    def test_did_client_live_anvil_integration(self):
        """End-to-end test spinning up real ephemeral Anvil node, deploying contract, and executing transactions."""
        with AnvilTestNode() as node:
            client = DIDClient(rpc_url=node.rpc_url, chain_id=node.chain_id, mock_mode=False)
            contract_addr = client.deploy_registry(deployer_address=ANVIL_DEFAULT_DEPLOYER)
            assert contract_addr.startswith("0x")

            # Check owner
            owner = client.get_owner()
            assert owner == ANVIL_DEFAULT_DEPLOYER.lower()

            # Deployer has default roles
            assert client.has_role(ANVIL_DEFAULT_DEPLOYER, ROLE_COLLECTOR) is True
            assert client.has_role(ANVIL_DEFAULT_DEPLOYER, ROLE_CUSTODIAN) is True

            # Grant Bob CUSTODIAN role
            client.grant_role(ANVIL_TEST_ADDR_1, ROLE_CUSTODIAN)
            assert client.has_role(ANVIL_TEST_ADDR_1, ROLE_CUSTODIAN) is True

            # Check initial nonce
            assert client.get_nonce(ANVIL_DEFAULT_DEPLOYER) == 0
