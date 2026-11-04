"""Forensics Decentralized Identity (DID) & ISO/IEC 27037 Chain of Custody Package."""

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

__all__ = [
    # DID Resolution
    "format_did",
    "parse_did",
    "resolve_did",
    "is_valid_did",
    # EIP-712
    "EIP712_TYPES",
    "ROLE_COLLECTOR",
    "ROLE_ANALYST",
    "ROLE_FIRST_RESPONDER",
    "ROLE_ZKML_VERIFIER",
    "ROLE_CUSTODIAN",
    "make_domain",
    "build_custody_transfer_typed_data",
    "build_attestation_typed_data",
    "sign_typed_data",
    "verify_typed_signature",
    # Artifacts & ISO/IEC 27037
    "canonical_hash",
    "compute_file_sha256",
    "create_ml_xai_attestation_payload",
    "create_zkml_attestation_payload",
    "scan_for_sensitive_leakage",
    # Client & Anvil
    "DIDClient",
    "AnvilTestNode",
    "ANVIL_DEFAULT_DEPLOYER",
]
