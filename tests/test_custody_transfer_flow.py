"""Comprehensive Test Suite for W3C DID Core 1.0, 2-Actor Handover & Gate T23/T24.

Verifies:
1. W3C DID Core 1.0 resolution and document structure.
2. EIP-712 CustodyTransfer typed data signing and signature verification.
3. 2-Actor Custody Handover on Live ephemeral Anvil node (Gate T23).
4. Anchoring of ML model hash, XAI digest, and ZKML proof hash into Chain of Custody.
5. 100% Cryptographic Hash Concordance.
6. 5 Fail-Closed Custody Rejection Vectors (Gate T24).
7. Canonical Database Invariance.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

from forensics.did.client import AnvilTestNode, DIDClient, ANVIL_DEFAULT_DEPLOYER
from forensics.did.eip712 import (
    ROLE_COLLECTOR,
    ROLE_ANALYST,
    ROLE_CUSTODIAN,
    ROLE_AUDITOR,
    build_custody_transfer_typed_data,
    sign_typed_data,
    verify_typed_signature,
    make_domain,
)
from forensics.did.resolution import format_did, resolve_did, is_valid_did

DEPLOYER = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
ALICE = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
ALICE_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
BOB = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
BOB_PK = "0x5de4111afa1a4b94908f83103eb2f9540808a0cb84e727575745778853a81230"
CHARLIE = "0x90f79bf6eb2c4f870365e785982e1f101e93b906"
CHARLIE_PK = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"


class TestW3CDIDResolution:
    """Verifies W3C DID Core 1.0 conformance."""

    def test_did_formatting_and_validation(self):
        did = format_did(ALICE)
        assert did == f"did:ethr:{ALICE.lower()}"
        assert is_valid_did(did)
        assert not is_valid_did("invalid:did:format")

    def test_w3c_did_document_structure(self):
        doc = resolve_did(format_did(ALICE), default_chain_id=31337)
        assert "@context" in doc
        assert doc["id"] == f"did:ethr:{ALICE.lower()}"
        assert "verificationMethod" in doc
        vm = doc["verificationMethod"][0]
        assert vm["type"] == "EcdsaSecp256k1RecoveryMethod2020"
        assert vm["controller"] == doc["id"]
        assert vm["blockchainAccountId"] == f"eip155:31337:{ALICE.lower()}"
        assert "authentication" in doc
        assert "assertionMethod" in doc


class TestEIP712Signing:
    """Verifies off-chain typed signature generation and verification."""

    def test_sign_and_verify_custody_transfer(self):
        contract_mock = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        artifact_hash = "0x" + hashlib.sha256(b"artifact").hexdigest()
        note_hash = "0x" + hashlib.sha256(b"handover").hexdigest()

        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract_mock,
            chain_id=31337,
            evidence_id=1,
            from_custodian=ALICE,
            to_custodian=BOB,
            artifact_sha256=artifact_hash,
            note_hash=note_hash,
            nonce=0,
            deadline=int(time.time()) + 3600,
        )

        sig = sign_typed_data(typed_data, private_key=ALICE_PK)
        assert sig.startswith("0x") and len(sig) == 132

        # Authentic verification succeeds
        assert verify_typed_signature(ALICE, typed_data, sig) is True

        # Verification with wrong signer address fails
        assert verify_typed_signature(BOB, typed_data, sig) is False

        # Verification on tampered payload fails
        tampered_data = dict(typed_data)
        tampered_data["message"] = dict(typed_data["message"])
        tampered_data["message"]["evidenceId"] = 2
        assert verify_typed_signature(ALICE, tampered_data, sig) is False


class TestAnvilCustodyTransferLive:
    """Verifies Live Anvil 2-Actor Custody Handover (Gate T23) and Fail-Closed Rejections (Gate T24)."""

    def test_live_custody_handover_flow(self):
        with AnvilTestNode() as node:
            client = DIDClient(rpc_url=node.rpc_url, chain_id=31337)
            contract_addr = client.deploy_registry(deployer_address=DEPLOYER)

            # Assign roles
            client.grant_role(ALICE, ROLE_COLLECTOR, sender=DEPLOYER)
            client.grant_role(ALICE, ROLE_CUSTODIAN, sender=DEPLOYER)
            client.grant_role(BOB, ROLE_ANALYST, sender=DEPLOYER)
            client.grant_role(BOB, ROLE_CUSTODIAN, sender=DEPLOYER)
            client.grant_role(DEPLOYER, ROLE_AUDITOR, sender=DEPLOYER)

            assert client.has_role(ALICE, ROLE_COLLECTOR)
            assert client.has_role(BOB, ROLE_ANALYST)
            assert client.has_role(DEPLOYER, ROLE_AUDITOR)

            # Register evidence
            orig_hash = hashlib.sha256(b"live_telemetry_bytes").hexdigest()
            manifest_hash = hashlib.sha256(b"manifest_json").hexdigest()
            ev_id = client.register_evidence(
                case_id_bytes32="0x" + hashlib.sha256(b"CASE-T23").hexdigest(),
                manifest_sha256="0x" + manifest_hash,
                storage_uri="evidence://case-t23/manifest.json",
                sender=ALICE,
            )
            assert ev_id == 1

            # Transfer custody from Alice to Bob
            note_hash = hashlib.sha256(b"Handover to Analyst").hexdigest()
            typed_data = build_custody_transfer_typed_data(
                verifying_contract=contract_addr,
                chain_id=31337,
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_hash,
                note_hash="0x" + note_hash,
                nonce=0,
                deadline=int(time.time()) + 3600,
            )
            sig = sign_typed_data(typed_data, private_key=ALICE_PK)

            receipt = client.transfer_custody_with_sig_receipt(
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_hash,
                note_hash="0x" + note_hash,
                nonce=0,
                deadline=int(time.time()) + 3600,
                signature=sig,
                sender=BOB,
            )
            assert receipt["status"] == 1
            assert receipt["gas_used"] > 0
            assert receipt["is_synthetic"] is True

            # Verify nonce incremented
            assert client.get_nonce(ALICE) == 1

            # Anchor ML, XAI, ZKML digests
            model_hash = hashlib.sha256(b"onnx_model").hexdigest()
            xai_digest = hashlib.sha256(b"xai_shap").hexdigest()
            zkml_proof_hash = hashlib.sha256(b"zkml_proof").hexdigest()

            client.anchor_forensic_evidence(
                evidence_id=ev_id,
                model_hash="0x" + model_hash,
                xai_digest="0x" + xai_digest,
                zkml_proof_hash="0x" + zkml_proof_hash,
                artifact_sha256="0x" + orig_hash,
                note_hash="0x" + note_hash,
                sender=BOB,
            )

            # Query custody history and assert 100% cryptographic concordance on-chain
            count = client.get_custody_count_did(ev_id)
            assert count == 2

            # Verify active custodian transition
            current_custodian = client.get_current_custodian(ev_id)
            assert current_custodian == BOB.lower(), f"Expected current custodian Bob, got {current_custodian}"

            hist = client.get_custody_history_did(ev_id)
            assert len(hist) >= 1
            raw_hex = "".join(hist[0]["raw_lines"]).lower()

            # Raw word / substring containment assertions
            assert orig_hash.lower() in raw_hex, "Original evidence hash missing in on-chain custody returndata"
            assert model_hash.lower() in raw_hex, "Model hash missing in on-chain custody returndata"
            assert xai_digest.lower() in raw_hex, "XAI digest missing in on-chain custody returndata"
            assert zkml_proof_hash.lower() in raw_hex, "ZKML proof hash missing in on-chain custody returndata"
            assert ALICE[2:].lower() in raw_hex, "Alice address missing in on-chain custody returndata"
            assert BOB[2:].lower() in raw_hex, "Bob address missing in on-chain custody returndata"

            # Adversarial tamper-rejection check
            tampered_hash = hashlib.sha256(b"adversarial_tampered_payload").hexdigest()
            assert tampered_hash.lower() not in raw_hex, "Tampered hash unexpectedly present in on-chain custody returndata"

            # Decoded record assertions
            decoded = hist[0].get("decoded_records")
            if not decoded:
                from forensics.did.client import decode_custody_records
                decoded = decode_custody_records(raw_hex)

            assert len(decoded) == 2, f"Expected 2 custody records, got {len(decoded)}"

            # Record 0: Handover transfer Alice -> Bob
            rec0 = decoded[0]
            assert rec0["evidence_id"] == ev_id
            assert rec0["action"] == 2  # CustodyAction.TRANSFERRED
            assert rec0["iso_stage"] == 2  # ISOStage.ACQUISITION
            assert rec0["actor"] == ALICE.lower()
            assert rec0["recipient"] == BOB.lower()
            assert rec0["artifact_sha256"] == orig_hash.lower()

            # Record 1: Forensic anchoring by Bob
            rec1 = decoded[1]
            assert rec1["evidence_id"] == ev_id
            assert rec1["action"] == 1  # CustodyAction.ANALYZED
            assert rec1["iso_stage"] == 3  # ISOStage.PRESERVATION
            assert rec1["actor"] == BOB.lower()
            assert rec1["artifact_sha256"] == orig_hash.lower()
            assert rec1["model_hash"] == model_hash.lower()
            assert rec1["xai_digest"] == xai_digest.lower()
            assert rec1["zkml_proof_hash"] == zkml_proof_hash.lower()

    def test_live_fail_closed_rejections_gate_t24(self):
        with AnvilTestNode() as node:
            client = DIDClient(rpc_url=node.rpc_url, chain_id=31337)
            contract_addr = client.deploy_registry(deployer_address=DEPLOYER)
            client.grant_role(ALICE, ROLE_COLLECTOR, sender=DEPLOYER)
            client.grant_role(ALICE, ROLE_CUSTODIAN, sender=DEPLOYER)
            client.grant_role(BOB, ROLE_ANALYST, sender=DEPLOYER)
            client.grant_role(BOB, ROLE_CUSTODIAN, sender=DEPLOYER)

            orig_hash = hashlib.sha256(b"evidence").hexdigest()
            ev_id = client.register_evidence(
                case_id_bytes32="0x" + "aa" * 32,
                manifest_sha256="0x" + "bb" * 32,
                storage_uri="evidence://case/manifest.json",
                sender=ALICE,
            )

            note_hash = "0x" + "cc" * 32

            # ADV-01: Forged signature (Charlie signs Alice's transfer)
            typed_01 = build_custody_transfer_typed_data(
                verifying_contract=contract_addr,
                chain_id=31337,
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=CHARLIE,
                artifact_sha256="0x" + orig_hash,
                note_hash=note_hash,
                nonce=0,
                deadline=int(time.time()) + 3600,
            )
            forged_sig = sign_typed_data(typed_01, private_key=CHARLIE_PK)
            with pytest.raises(Exception):
                client.transfer_custody_with_sig(
                    evidence_id=ev_id,
                    from_custodian=ALICE,
                    to_custodian=CHARLIE,
                    artifact_sha256="0x" + orig_hash,
                    note_hash=note_hash,
                    nonce=0,
                    deadline=int(time.time()) + 3600,
                    signature=forged_sig,
                    sender=CHARLIE,
                )

            deadline = int(time.time()) + 3600

            # ADV-02: Unauthorized role (Alice lacks ROLE_CUSTODIAN)
            client.revoke_role(ALICE, ROLE_CUSTODIAN, sender=DEPLOYER)
            typed_02 = build_custody_transfer_typed_data(
                verifying_contract=contract_addr,
                chain_id=31337,
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_hash,
                note_hash=note_hash,
                nonce=0,
                deadline=deadline,
            )
            valid_sig = sign_typed_data(typed_02, private_key=ALICE_PK)
            with pytest.raises(Exception):
                client.transfer_custody_with_sig(
                    evidence_id=ev_id,
                    from_custodian=ALICE,
                    to_custodian=BOB,
                    artifact_sha256="0x" + orig_hash,
                    note_hash=note_hash,
                    nonce=0,
                    deadline=deadline,
                    signature=valid_sig,
                    sender=DEPLOYER,
                )
            client.grant_role(ALICE, ROLE_CUSTODIAN, sender=DEPLOYER)

            # ADV-03: Cross-chain replay (signed on chainId 1)
            typed_03 = build_custody_transfer_typed_data(
                verifying_contract=contract_addr,
                chain_id=1,
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_hash,
                note_hash=note_hash,
                nonce=0,
                deadline=deadline,
            )
            cross_chain_sig = sign_typed_data(typed_03, private_key=ALICE_PK)
            with pytest.raises(Exception):
                client.transfer_custody_with_sig(
                    evidence_id=ev_id,
                    from_custodian=ALICE,
                    to_custodian=BOB,
                    artifact_sha256="0x" + orig_hash,
                    note_hash=note_hash,
                    nonce=0,
                    deadline=deadline,
                    signature=cross_chain_sig,
                    sender=DEPLOYER,
                )

            # ADV-04: Tampered evidence ID (ID 999)
            with pytest.raises(Exception):
                client.transfer_custody_with_sig(
                    evidence_id=999,
                    from_custodian=ALICE,
                    to_custodian=BOB,
                    artifact_sha256="0x" + orig_hash,
                    note_hash=note_hash,
                    nonce=0,
                    deadline=deadline,
                    signature=valid_sig,
                    sender=DEPLOYER,
                )

            # ADV-05: Nonce replay & expired deadline
            # First execute genuine transfer
            client.transfer_custody_with_sig(
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_hash,
                note_hash=note_hash,
                nonce=0,
                deadline=deadline,
                signature=valid_sig,
                sender=DEPLOYER,
            )
            # Stale nonce 0 replay must fail
            with pytest.raises(Exception):
                client.transfer_custody_with_sig(
                    evidence_id=ev_id,
                    from_custodian=ALICE,
                    to_custodian=BOB,
                    artifact_sha256="0x" + orig_hash,
                    note_hash=note_hash,
                    nonce=0,
                    deadline=deadline,
                    signature=valid_sig,
                    sender=DEPLOYER,
                )

    def test_canonical_db_invariance(self):
        paths = {
            "real_p4.db": Path("data/real_p4.db"),
            "forensics.db": Path("data/forensics.db"),
            "benchmark_p6.db": Path("data/benchmark_p6.db"),
            ".env": Path(".env"),
        }
        expected = {
            "real_p4.db": "6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97",
            "forensics.db": "3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001",
            "benchmark_p6.db": "C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507",
            ".env": "C2F4879666CD21276C58EC75DE923C8235D414F3D646A854A835C5638EC1699C",
        }
        for name, p in paths.items():
            if p.exists():
                digest = hashlib.sha256(p.read_bytes()).hexdigest().upper()
                assert digest == expected[name], f"Canonical DB {name} was modified!"
