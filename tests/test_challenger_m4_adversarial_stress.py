"""Adversarial Stress Test Suite for Milestone M4 (Gates T23, T24, Anvil Lifecycle & DB Invariance).

Author: challenger_v6_M4_2 (Empirical Challenger)
Target: scripts/run_custody_handover_demo.py, EvidenceRegistryDID.sol, forensics/did/*
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from forensics.did.client import AnvilTestNode, DIDClient, ANVIL_DEFAULT_DEPLOYER
from forensics.did.eip712 import (
    ROLE_COLLECTOR,
    ROLE_ANALYST,
    ROLE_CUSTODIAN,
    ROLE_AUDITOR,
    ROLE_FIRST_RESPONDER,
    ROLE_ZKML_VERIFIER,
    build_custody_transfer_typed_data,
    sign_typed_data,
    verify_typed_signature,
    make_domain,
)
from forensics.did.resolution import format_did, resolve_did, is_valid_did

# Standard Anvil Accounts & Private Keys
DEPLOYER = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
DEPLOYER_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

ALICE = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
ALICE_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

BOB = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
BOB_PK = "0x5de4111afa1a4b94908f83103eb2f9540808a0cb84e727575745778853a81230"

CHARLIE = "0x90f79bf6eb2c4f870365e785982e1f101e93b906"
CHARLIE_PK = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"

# Curve order for secp256k1
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_N_DIV_2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0


@pytest.fixture(scope="module")
def anvil_session():
    """Module-level live Anvil node for Gate T24 fail-closed stress testing."""
    with AnvilTestNode(chain_id=31337) as node:
        client = DIDClient(rpc_url=node.rpc_url, chain_id=31337)
        contract_addr = client.deploy_registry(deployer_address=DEPLOYER)

        # Grant roles
        client.grant_role(ALICE, ROLE_COLLECTOR, sender=DEPLOYER)
        client.grant_role(ALICE, ROLE_CUSTODIAN, sender=DEPLOYER)
        client.grant_role(BOB, ROLE_ANALYST, sender=DEPLOYER)
        client.grant_role(BOB, ROLE_CUSTODIAN, sender=DEPLOYER)
        client.grant_role(CHARLIE, ROLE_CUSTODIAN, sender=DEPLOYER)  # Charlie is a custodian but not holding evidence

        # Register standard evidence ID 1 under Alice
        orig_hash = hashlib.sha256(b"canonical_payload_evidence_1").hexdigest()
        manifest_hash = hashlib.sha256(b"canonical_manifest_1").hexdigest()
        ev_id = client.register_evidence(
            case_id_bytes32="0x" + hashlib.sha256(b"CASE-STRESS-01").hexdigest(),
            manifest_sha256="0x" + manifest_hash,
            storage_uri="evidence://stress/manifest.json",
            sender=ALICE,
        )

        yield {
            "node": node,
            "client": client,
            "contract": contract_addr,
            "ev_id": ev_id,
            "orig_hash": orig_hash,
        }


class TestGateT24FailClosedEdgeCases:
    """Stress tests every fail-closed edge case of Gate T24 on live Anvil."""

    def test_forged_signature_mismatched_signer(self, anvil_session):
        """Charlie signs a handover claiming fromCustodian is Alice."""
        client: DIDClient = anvil_session["client"]
        contract = anvil_session["contract"]
        ev_id = anvil_session["ev_id"]
        orig_hash = anvil_session["orig_hash"]
        note_hash = "0x" + hashlib.sha256(b"forged_note").hexdigest()

        alice_nonce = client.get_nonce(ALICE)
        deadline = int(time.time()) + 3600

        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=ev_id,
            from_custodian=ALICE,
            to_custodian=CHARLIE,
            artifact_sha256="0x" + orig_hash,
            note_hash=note_hash,
            nonce=alice_nonce,
            deadline=deadline,
        )
        forged_sig = sign_typed_data(typed_data, private_key=CHARLIE_PK)

        with pytest.raises(RuntimeError) as exc_info:
            client.transfer_custody_with_sig(
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=CHARLIE,
                artifact_sha256="0x" + orig_hash,
                note_hash=note_hash,
                nonce=alice_nonce,
                deadline=deadline,
                signature=forged_sig,
                sender=CHARLIE,
            )
        assert "CAST_EXIT" in str(exc_info.value)

    def test_tampered_signature_flipped_byte(self, anvil_session):
        """Valid Alice signature has a byte flipped in the signature payload."""
        client: DIDClient = anvil_session["client"]
        contract = anvil_session["contract"]
        ev_id = anvil_session["ev_id"]
        orig_hash = anvil_session["orig_hash"]
        note_hash = "0x" + hashlib.sha256(b"flipped_byte_note").hexdigest()

        alice_nonce = client.get_nonce(ALICE)
        deadline = int(time.time()) + 3600

        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=ev_id,
            from_custodian=ALICE,
            to_custodian=BOB,
            artifact_sha256="0x" + orig_hash,
            note_hash=note_hash,
            nonce=alice_nonce,
            deadline=deadline,
        )
        valid_sig = sign_typed_data(typed_data, private_key=ALICE_PK)

        # Corrupt one hex character in the 'r' component
        sig_raw = valid_sig[2:]
        corrupted_char = '0' if sig_raw[10] != '0' else '1'
        corrupted_sig = "0x" + sig_raw[:10] + corrupted_char + sig_raw[11:]

        with pytest.raises(RuntimeError) as exc_info:
            client.transfer_custody_with_sig(
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_hash,
                note_hash=note_hash,
                nonce=alice_nonce,
                deadline=deadline,
                signature=corrupted_sig,
                sender=DEPLOYER,
            )
        assert "CAST_EXIT" in str(exc_info.value)

    def test_malleable_s_signature_rejection(self, anvil_session):
        """EIP-2 malleability rejection: s > secp256k1n / 2 must revert."""
        client: DIDClient = anvil_session["client"]
        contract = anvil_session["contract"]
        ev_id = anvil_session["ev_id"]
        orig_hash = anvil_session["orig_hash"]
        note_hash = "0x" + hashlib.sha256(b"malleability_note").hexdigest()

        alice_nonce = client.get_nonce(ALICE)
        deadline = int(time.time()) + 3600

        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=ev_id,
            from_custodian=ALICE,
            to_custodian=BOB,
            artifact_sha256="0x" + orig_hash,
            note_hash=note_hash,
            nonce=alice_nonce,
            deadline=deadline,
        )
        valid_sig = sign_typed_data(typed_data, private_key=ALICE_PK)
        sig_bytes = bytes.fromhex(valid_sig[2:])
        r = sig_bytes[:32]
        s_int = int.from_bytes(sig_bytes[32:64], "big")
        v = sig_bytes[64]

        # Invert s to make s > N/2
        s_malleable = SECP256K1_N - s_int
        assert s_malleable > SECP256K1_N_DIV_2

        # Invert v
        v_malleable = 27 if v == 28 else 28
        malleable_sig_bytes = r + s_malleable.to_bytes(32, "big") + bytes([v_malleable])
        malleable_sig = "0x" + malleable_sig_bytes.hex()

        with pytest.raises(RuntimeError) as exc_info:
            client.transfer_custody_with_sig(
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_hash,
                note_hash=note_hash,
                nonce=alice_nonce,
                deadline=deadline,
                signature=malleable_sig,
                sender=DEPLOYER,
            )
        assert "CAST_EXIT" in str(exc_info.value)

    def test_invalid_v_signature_rejection(self, anvil_session):
        """Signature with invalid recovery id v (not 27 and not 28) must revert."""
        client: DIDClient = anvil_session["client"]
        contract = anvil_session["contract"]
        ev_id = anvil_session["ev_id"]
        orig_hash = anvil_session["orig_hash"]
        note_hash = "0x" + hashlib.sha256(b"invalid_v_note").hexdigest()

        alice_nonce = client.get_nonce(ALICE)
        deadline = int(time.time()) + 3600

        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=ev_id,
            from_custodian=ALICE,
            to_custodian=BOB,
            artifact_sha256="0x" + orig_hash,
            note_hash=note_hash,
            nonce=alice_nonce,
            deadline=deadline,
        )
        valid_sig = sign_typed_data(typed_data, private_key=ALICE_PK)
        sig_bytes = bytes.fromhex(valid_sig[2:])

        # Set v = 30
        bad_v_sig = "0x" + sig_bytes[:64].hex() + "1e"

        with pytest.raises(RuntimeError) as exc_info:
            client.transfer_custody_with_sig(
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_hash,
                note_hash=note_hash,
                nonce=alice_nonce,
                deadline=deadline,
                signature=bad_v_sig,
                sender=DEPLOYER,
            )
        assert "CAST_EXIT" in str(exc_info.value)

    def test_invalid_signature_length_rejection(self, anvil_session):
        """Signature with length != 65 bytes must revert."""
        client: DIDClient = anvil_session["client"]
        contract = anvil_session["contract"]
        ev_id = anvil_session["ev_id"]
        orig_hash = anvil_session["orig_hash"]
        note_hash = "0x" + hashlib.sha256(b"bad_len_note").hexdigest()

        alice_nonce = client.get_nonce(ALICE)
        deadline = int(time.time()) + 3600

        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=ev_id,
            from_custodian=ALICE,
            to_custodian=BOB,
            artifact_sha256="0x" + orig_hash,
            note_hash=note_hash,
            nonce=alice_nonce,
            deadline=deadline,
        )
        valid_sig = sign_typed_data(typed_data, private_key=ALICE_PK)

        # Truncate to 64 bytes
        truncated_sig = valid_sig[:-2]

        with pytest.raises(RuntimeError) as exc_info:
            client.transfer_custody_with_sig(
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_hash,
                note_hash=note_hash,
                nonce=alice_nonce,
                deadline=deadline,
                signature=truncated_sig,
                sender=DEPLOYER,
            )
        assert "CAST_EXIT" in str(exc_info.value)

    def test_unauthorized_from_custodian_role(self, anvil_session):
        """fromCustodian lacks ROLE_CUSTODIAN."""
        client: DIDClient = anvil_session["client"]
        contract = anvil_session["contract"]
        ev_id = anvil_session["ev_id"]
        orig_hash = anvil_session["orig_hash"]
        note_hash = "0x" + hashlib.sha256(b"unauth_role_from").hexdigest()

        # Temporarily revoke ROLE_CUSTODIAN from Alice
        client.revoke_role(ALICE, ROLE_CUSTODIAN, sender=DEPLOYER)
        assert not client.has_role(ALICE, ROLE_CUSTODIAN)

        alice_nonce = client.get_nonce(ALICE)
        deadline = int(time.time()) + 3600

        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=ev_id,
            from_custodian=ALICE,
            to_custodian=BOB,
            artifact_sha256="0x" + orig_hash,
            note_hash=note_hash,
            nonce=alice_nonce,
            deadline=deadline,
        )
        valid_sig = sign_typed_data(typed_data, private_key=ALICE_PK)

        try:
            with pytest.raises(RuntimeError) as exc_info:
                client.transfer_custody_with_sig(
                    evidence_id=ev_id,
                    from_custodian=ALICE,
                    to_custodian=BOB,
                    artifact_sha256="0x" + orig_hash,
                    note_hash=note_hash,
                    nonce=alice_nonce,
                    deadline=deadline,
                    signature=valid_sig,
                    sender=DEPLOYER,
                )
            assert "CAST_EXIT" in str(exc_info.value)
        finally:
            client.grant_role(ALICE, ROLE_CUSTODIAN, sender=DEPLOYER)

    def test_unauthorized_to_custodian_role(self, anvil_session):
        """toCustodian lacks ROLE_CUSTODIAN."""
        client: DIDClient = anvil_session["client"]
        contract = anvil_session["contract"]
        ev_id = anvil_session["ev_id"]
        orig_hash = anvil_session["orig_hash"]
        note_hash = "0x" + hashlib.sha256(b"unauth_role_to").hexdigest()

        # Temporarily revoke ROLE_CUSTODIAN from Bob
        client.revoke_role(BOB, ROLE_CUSTODIAN, sender=DEPLOYER)
        assert not client.has_role(BOB, ROLE_CUSTODIAN)

        alice_nonce = client.get_nonce(ALICE)
        deadline = int(time.time()) + 3600

        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=ev_id,
            from_custodian=ALICE,
            to_custodian=BOB,
            artifact_sha256="0x" + orig_hash,
            note_hash=note_hash,
            nonce=alice_nonce,
            deadline=deadline,
        )
        valid_sig = sign_typed_data(typed_data, private_key=ALICE_PK)

        try:
            with pytest.raises(RuntimeError) as exc_info:
                client.transfer_custody_with_sig(
                    evidence_id=ev_id,
                    from_custodian=ALICE,
                    to_custodian=BOB,
                    artifact_sha256="0x" + orig_hash,
                    note_hash=note_hash,
                    nonce=alice_nonce,
                    deadline=deadline,
                    signature=valid_sig,
                    sender=DEPLOYER,
                )
            assert "CAST_EXIT" in str(exc_info.value)
        finally:
            client.grant_role(BOB, ROLE_CUSTODIAN, sender=DEPLOYER)

    def test_non_current_custodian_hijack(self, anvil_session):
        """Charlie has ROLE_CUSTODIAN, but is NOT the current custodian of evidence 1."""
        client: DIDClient = anvil_session["client"]
        contract = anvil_session["contract"]
        ev_id = anvil_session["ev_id"]
        orig_hash = anvil_session["orig_hash"]
        note_hash = "0x" + hashlib.sha256(b"hijack_note").hexdigest()

        charlie_nonce = client.get_nonce(CHARLIE)
        deadline = int(time.time()) + 3600

        # Charlie attempts to transfer Alice's evidence to Bob
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=ev_id,
            from_custodian=CHARLIE,
            to_custodian=BOB,
            artifact_sha256="0x" + orig_hash,
            note_hash=note_hash,
            nonce=charlie_nonce,
            deadline=deadline,
        )
        charlie_sig = sign_typed_data(typed_data, private_key=CHARLIE_PK)

        with pytest.raises(RuntimeError) as exc_info:
            client.transfer_custody_with_sig(
                evidence_id=ev_id,
                from_custodian=CHARLIE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_hash,
                note_hash=note_hash,
                nonce=charlie_nonce,
                deadline=deadline,
                signature=charlie_sig,
                sender=CHARLIE,
            )
        assert "CAST_EXIT" in str(exc_info.value)

    def test_chain_id_replay_isolation(self, anvil_session):
        """Signature produced for Sepolia (11155111) or Mainnet (1) must fail on Anvil (31337)."""
        client: DIDClient = anvil_session["client"]
        contract = anvil_session["contract"]
        ev_id = anvil_session["ev_id"]
        orig_hash = anvil_session["orig_hash"]
        note_hash = "0x" + hashlib.sha256(b"chain_replay_note").hexdigest()

        alice_nonce = client.get_nonce(ALICE)
        deadline = int(time.time()) + 3600

        for foreign_chain_id in [1, 11155111, 1337]:
            typed_data = build_custody_transfer_typed_data(
                verifying_contract=contract,
                chain_id=foreign_chain_id,
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_hash,
                note_hash=note_hash,
                nonce=alice_nonce,
                deadline=deadline,
            )
            foreign_sig = sign_typed_data(typed_data, private_key=ALICE_PK)

            with pytest.raises(RuntimeError) as exc_info:
                client.transfer_custody_with_sig(
                    evidence_id=ev_id,
                    from_custodian=ALICE,
                    to_custodian=BOB,
                    artifact_sha256="0x" + orig_hash,
                    note_hash=note_hash,
                    nonce=alice_nonce,
                    deadline=deadline,
                    signature=foreign_sig,
                    sender=DEPLOYER,
                )
            assert "CAST_EXIT" in str(exc_info.value)

    def test_tampered_evidence_id_nonexistent(self, anvil_session):
        """Transfer non-existent evidenceId 0 or 9999."""
        client: DIDClient = anvil_session["client"]
        contract = anvil_session["contract"]
        orig_hash = anvil_session["orig_hash"]
        note_hash = "0x" + hashlib.sha256(b"nonexistent_id").hexdigest()
        alice_nonce = client.get_nonce(ALICE)
        deadline = int(time.time()) + 3600

        for bad_id in [0, 9999]:
            typed_data = build_custody_transfer_typed_data(
                verifying_contract=contract,
                chain_id=31337,
                evidence_id=bad_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_hash,
                note_hash=note_hash,
                nonce=alice_nonce,
                deadline=deadline,
            )
            sig = sign_typed_data(typed_data, private_key=ALICE_PK)

            with pytest.raises(RuntimeError) as exc_info:
                client.transfer_custody_with_sig(
                    evidence_id=bad_id,
                    from_custodian=ALICE,
                    to_custodian=BOB,
                    artifact_sha256="0x" + orig_hash,
                    note_hash=note_hash,
                    nonce=alice_nonce,
                    deadline=deadline,
                    signature=sig,
                    sender=DEPLOYER,
                )
            assert "CAST_EXIT" in str(exc_info.value)

    def test_tampered_payload_hash_conflict(self, anvil_session):
        """Alice signs for artifactSha256 A, but transaction submits artifactSha256 B."""
        client: DIDClient = anvil_session["client"]
        contract = anvil_session["contract"]
        ev_id = anvil_session["ev_id"]
        orig_hash = anvil_session["orig_hash"]
        tampered_hash = hashlib.sha256(b"tampered_payload_hash_conflict").hexdigest()
        note_hash = "0x" + hashlib.sha256(b"hash_conflict_note").hexdigest()

        alice_nonce = client.get_nonce(ALICE)
        deadline = int(time.time()) + 3600

        # Sign with original hash
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=ev_id,
            from_custodian=ALICE,
            to_custodian=BOB,
            artifact_sha256="0x" + orig_hash,
            note_hash=note_hash,
            nonce=alice_nonce,
            deadline=deadline,
        )
        sig = sign_typed_data(typed_data, private_key=ALICE_PK)

        # Submit with tampered hash
        with pytest.raises(RuntimeError) as exc_info:
            client.transfer_custody_with_sig(
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + tampered_hash,
                note_hash=note_hash,
                nonce=alice_nonce,
                deadline=deadline,
                signature=sig,
                sender=DEPLOYER,
            )
        assert "CAST_EXIT" in str(exc_info.value)

    def test_zero_artifact_sha256_rejection(self, anvil_session):
        """artifactSha256 = bytes32(0) must revert ZeroValue()."""
        client: DIDClient = anvil_session["client"]
        contract = anvil_session["contract"]
        ev_id = anvil_session["ev_id"]
        note_hash = "0x" + hashlib.sha256(b"zero_artifact").hexdigest()
        alice_nonce = client.get_nonce(ALICE)
        deadline = int(time.time()) + 3600
        zero_hash = "0x" + "00" * 32

        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=ev_id,
            from_custodian=ALICE,
            to_custodian=BOB,
            artifact_sha256=zero_hash,
            note_hash=note_hash,
            nonce=alice_nonce,
            deadline=deadline,
        )
        sig = sign_typed_data(typed_data, private_key=ALICE_PK)

        with pytest.raises(RuntimeError) as exc_info:
            client.transfer_custody_with_sig(
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256=zero_hash,
                note_hash=note_hash,
                nonce=alice_nonce,
                deadline=deadline,
                signature=sig,
                sender=DEPLOYER,
            )
        assert "CAST_EXIT" in str(exc_info.value)

    def test_out_of_order_nonce_rejection(self, anvil_session):
        """Nonce mismatch (e.g. provided nonce = current + 5) must revert."""
        client: DIDClient = anvil_session["client"]
        contract = anvil_session["contract"]
        ev_id = anvil_session["ev_id"]
        orig_hash = anvil_session["orig_hash"]
        note_hash = "0x" + hashlib.sha256(b"future_nonce").hexdigest()

        alice_nonce = client.get_nonce(ALICE)
        deadline = int(time.time()) + 3600

        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=ev_id,
            from_custodian=ALICE,
            to_custodian=BOB,
            artifact_sha256="0x" + orig_hash,
            note_hash=note_hash,
            nonce=alice_nonce + 5,
            deadline=deadline,
        )
        sig = sign_typed_data(typed_data, private_key=ALICE_PK)

        with pytest.raises(RuntimeError) as exc_info:
            client.transfer_custody_with_sig(
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_hash,
                note_hash=note_hash,
                nonce=alice_nonce + 5,
                deadline=deadline,
                signature=sig,
                sender=DEPLOYER,
            )
        assert "CAST_EXIT" in str(exc_info.value)

    def test_expired_deadline_rejection(self, anvil_session):
        """Expired deadline (block.timestamp > deadline) must revert."""
        client: DIDClient = anvil_session["client"]
        contract = anvil_session["contract"]
        ev_id = anvil_session["ev_id"]
        orig_hash = anvil_session["orig_hash"]
        note_hash = "0x" + hashlib.sha256(b"expired_deadline").hexdigest()

        alice_nonce = client.get_nonce(ALICE)
        expired_deadline = int(time.time()) - 3600  # 1 hour in the past

        typed_data = build_custody_transfer_typed_data(
            verifying_contract=contract,
            chain_id=31337,
            evidence_id=ev_id,
            from_custodian=ALICE,
            to_custodian=BOB,
            artifact_sha256="0x" + orig_hash,
            note_hash=note_hash,
            nonce=alice_nonce,
            deadline=expired_deadline,
        )
        sig = sign_typed_data(typed_data, private_key=ALICE_PK)

        with pytest.raises(RuntimeError) as exc_info:
            client.transfer_custody_with_sig(
                evidence_id=ev_id,
                from_custodian=ALICE,
                to_custodian=BOB,
                artifact_sha256="0x" + orig_hash,
                note_hash=note_hash,
                nonce=alice_nonce,
                deadline=expired_deadline,
                signature=sig,
                sender=DEPLOYER,
            )
        assert "CAST_EXIT" in str(exc_info.value)


class TestAnvilLifecycleStress:
    """Stress tests ephemeral Anvil port collisions and process SIGKILL recovery."""

    def test_port_collision_fail_fast(self):
        """Occupying a port with an existing socket must fail fast (not hang)."""
        # Bind and hold a localhost port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        occupied_port = s.getsockname()[1]

        try:
            start_time = time.time()
            node = AnvilTestNode(port=occupied_port, chain_id=31337)
            with pytest.raises(RuntimeError) as exc_info:
                with node:
                    pass
            elapsed = time.time() - start_time
            # Must fail within ~15 seconds timeout
            assert elapsed < 15.0, f"Port collision hung for {elapsed:.2f}s!"
            assert "ANVIL_START_TIMEOUT" in str(exc_info.value)
        finally:
            s.close()

    def test_dynamic_port_collision_avoidance(self):
        """Multiple sequential and concurrent nodes dynamically select distinct free ports."""
        with AnvilTestNode() as node1:
            port1 = node1.port
            with AnvilTestNode() as node2:
                port2 = node2.port
                assert port1 != port2, f"Port collision occurred: both got {port1}"
                # Verify both are responsive
                client1 = DIDClient(rpc_url=node1.rpc_url)
                client2 = DIDClient(rpc_url=node2.rpc_url)
                c1 = client1.deploy_registry(deployer_address=DEPLOYER)
                c2 = client2.deploy_registry(deployer_address=DEPLOYER)
                assert c1.startswith("0x") and c2.startswith("0x")

    def test_abrupt_process_sigkill_recovery(self):
        """Killing Anvil with SIGKILL does not leave leaked resources or prevent new node startup."""
        node = AnvilTestNode()
        with node:
            assert node.proc is not None
            # Abrupt kill
            node.proc.kill()
            node.proc.wait(timeout=3)
            assert node.proc.poll() is not None

        # Clean context exit should succeed without uncaught errors
        # Now immediately spawn another node and verify full functionality
        with AnvilTestNode() as node_recovered:
            client = DIDClient(rpc_url=node_recovered.rpc_url)
            contract = client.deploy_registry(deployer_address=DEPLOYER)
            assert contract.startswith("0x")


class TestCanonicalDatabaseInvarianceChallenger:
    """Strict empirical verification of 100% bitwise invariance of all 4 canonical databases."""

    CANONICAL_HASHES = {
        "data/real_p4.db": "6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97",
        "data/forensics.db": "3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001",
        "data/benchmark_p6.db": "C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507",
        ".env": "C2F4879666CD21276C58EC75DE923C8235D414F3D646A854A835C5638EC1699C",
    }

    def test_canonical_databases_bitwise_identical(self):
        root = Path(__file__).resolve().parents[1]
        for rel_path, expected_hash in self.CANONICAL_HASHES.items():
            abs_path = root / rel_path
            assert abs_path.exists(), f"Canonical file missing: {rel_path}"
            computed_hash = hashlib.sha256(abs_path.read_bytes()).hexdigest().upper()
            assert computed_hash == expected_hash, (
                f"CORRUPTION DETECTED in {rel_path}!\n"
                f"Expected: {expected_hash}\n"
                f"Actual:   {computed_hash}"
            )
