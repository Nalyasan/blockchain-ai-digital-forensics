"""EIP-712 Typed Structured Data Schemas and Verification for Digital Evidence.

Supports:
- CustodyTransfer: Peer-to-peer evidence custody handover
- ForensicAttestation: Certification of ML, XAI, ZKML, or triage artifacts
- Signing and verification using bundled Foundry cast.exe and standard library
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from typing import Any

from forensics.onchain import _run_cast, CAST_BIN

ROLE_COLLECTOR = "0x8c6beae43068e1c9c302c890c7b1cccac9b07bc3283a7d3e487d52efe260573a"
ROLE_ANALYST = "0x27d4f0a2779e7e00b0931df5ca5c66815b75207ee894b2681b2e716fb14a750c"
ROLE_FIRST_RESPONDER = "0x1a6ae8369dd76795d37c9ef7c41126b81a1e2941f2f35568660d364bac08c39a"
ROLE_ZKML_VERIFIER = "0x7a450b5ecc5c338e0a5d0f01dcad41a5abd9419ffb5d295439e2310437fbe7a2"
ROLE_CUSTODIAN = "0x171bc1a6295b6943cf90a36a7d93ba90290d4d493379ca06d1e1c8955ca2b8ee"

EIP712_TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ],
    "CustodyTransfer": [
        {"name": "evidenceId", "type": "uint256"},
        {"name": "fromCustodian", "type": "address"},
        {"name": "toCustodian", "type": "address"},
        {"name": "artifactSha256", "type": "bytes32"},
        {"name": "noteHash", "type": "bytes32"},
        {"name": "nonce", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ],
    "ForensicAttestation": [
        {"name": "evidenceId", "type": "uint256"},
        {"name": "attestor", "type": "address"},
        {"name": "role", "type": "bytes32"},
        {"name": "artifactHash", "type": "bytes32"},
        {"name": "statementHash", "type": "bytes32"},
        {"name": "nonce", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ],
}


def _ensure_0x_bytes32(val: str) -> str:
    """Formats string into a 0x-prefixed 32-byte hex string."""
    v = val.strip()
    if not v.startswith("0x") and not v.startswith("0X"):
        v = "0x" + v
    if len(v) != 66 or not re.fullmatch(r"^0x[0-9a-fA-F]{64}$", v):
        raise ValueError(f"INVALID_BYTES32: Expected 32-byte hex string, got '{val}'")
    return v.lower()


def _ensure_0x_address(val: str) -> str:
    """Formats string into a 0x-prefixed 20-byte address."""
    v = val.strip()
    if not v.startswith("0x") and not v.startswith("0X"):
        v = "0x" + v
    if len(v) != 42 or not re.fullmatch(r"^0x[0-9a-fA-F]{40}$", v):
        raise ValueError(f"INVALID_ADDRESS: Expected 20-byte hex address, got '{val}'")
    return v.lower()


def make_domain(
    verifying_contract: str,
    chain_id: int = 31337,
    name: str = "EvidenceRegistryDID",
    version: str = "1",
) -> dict[str, Any]:
    """Builds the canonical EIP-712 domain separator dictionary."""
    return {
        "name": name,
        "version": version,
        "chainId": int(chain_id),
        "verifyingContract": _ensure_0x_address(verifying_contract),
    }


def build_custody_transfer_typed_data(
    verifying_contract: str,
    chain_id: int,
    evidence_id: int,
    from_custodian: str,
    to_custodian: str,
    artifact_sha256: str,
    note_hash: str,
    nonce: int,
    deadline: int,
) -> dict[str, Any]:
    """Constructs the complete EIP-712 JSON dictionary for a CustodyTransfer."""
    return {
        "types": {
            "EIP712Domain": EIP712_TYPES["EIP712Domain"],
            "CustodyTransfer": EIP712_TYPES["CustodyTransfer"],
        },
        "primaryType": "CustodyTransfer",
        "domain": make_domain(verifying_contract, chain_id),
        "message": {
            "evidenceId": int(evidence_id),
            "fromCustodian": _ensure_0x_address(from_custodian),
            "toCustodian": _ensure_0x_address(to_custodian),
            "artifactSha256": _ensure_0x_bytes32(artifact_sha256),
            "noteHash": _ensure_0x_bytes32(note_hash),
            "nonce": int(nonce),
            "deadline": int(deadline),
        },
    }


def build_attestation_typed_data(
    verifying_contract: str,
    chain_id: int,
    evidence_id: int,
    attestor: str,
    role: str,
    artifact_hash: str,
    statement_hash: str,
    nonce: int,
    deadline: int,
) -> dict[str, Any]:
    """Constructs the complete EIP-712 JSON dictionary for a ForensicAttestation."""
    return {
        "types": {
            "EIP712Domain": EIP712_TYPES["EIP712Domain"],
            "ForensicAttestation": EIP712_TYPES["ForensicAttestation"],
        },
        "primaryType": "ForensicAttestation",
        "domain": make_domain(verifying_contract, chain_id),
        "message": {
            "evidenceId": int(evidence_id),
            "attestor": _ensure_0x_address(attestor),
            "role": _ensure_0x_bytes32(role),
            "artifactHash": _ensure_0x_bytes32(artifact_hash),
            "statementHash": _ensure_0x_bytes32(statement_hash),
            "nonce": int(nonce),
            "deadline": int(deadline),
        },
    }


def sign_typed_data(
    typed_data: dict[str, Any],
    private_key: str | None = None,
    account: str | None = None,
    password_file: str | None = None,
) -> str:
    """Signs an EIP-712 typed data payload using Foundry cast.exe.

    Args:
        typed_data: Standard EIP-712 dictionary (types, domain, primaryType, message).
        private_key: Hex private key (for local development / Anvil only).
        account: Keystore account name (for live networks like Sepolia).
        password_file: Path to password file for encrypted keystore.

    Returns:
        65-byte ECDSA signature string formatted as "0x...".
    """
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(typed_data, f)
        temp_path = f.name

    try:
        args = ["wallet", "sign", "--data", "--from-file", temp_path]
        if private_key:
            args += ["--private-key", private_key]
        elif account:
            args += ["--account", account]
            if password_file:
                args += ["--password-file", password_file]
        else:
            raise ValueError("AUTH_REQUIRED: Either private_key or account must be specified")

        sig = _run_cast(args)
        if not sig.startswith("0x") or len(sig) != 132:
            raise RuntimeError(f"SIGNATURE_INVALID: Expected 65-byte hex signature, got '{sig}'")
        return sig
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def verify_typed_signature(
    signer_address: str,
    typed_data: dict[str, Any],
    signature: str,
) -> bool:
    """Verifies that an EIP-712 signature matches the claimed signer address using cast.exe.

    Args:
        signer_address: 20-byte Ethereum address.
        typed_data: EIP-712 dictionary.
        signature: 65-byte hex signature string.

    Returns:
        True if signature is valid and signer matches, False otherwise.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(typed_data, f)
        temp_path = f.name

    try:
        args = [
            "wallet", "verify",
            "--address", _ensure_0x_address(signer_address),
            "--data", "--from-file", temp_path,
            signature,
        ]
        _run_cast(args)
        return True
    except Exception:
        return False
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
