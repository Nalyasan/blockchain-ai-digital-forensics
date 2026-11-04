"""ERC-1056 Decentralized Identity (DID) Formatting, Parsing, and Resolution.

Conforms to W3C DID Core 1.0 and ERC-1056 Ethereum DID Registry specifications.
Canonical format: did:ethr:0x<40-hex-characters-lowercase>
"""
from __future__ import annotations

import re
from typing import Any

ETH_ADDRESS_REGEX = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX_40_REGEX = re.compile(r"^[0-9a-fA-F]{40}$")
DID_ETHR_REGEX = re.compile(
    r"^did:ethr:(?:(0x[0-9a-fA-F]+|[0-9a-zA-Z_-]+):)?(0x[0-9a-fA-F]{40})$"
)


def format_did(address: str, chain_id: int | None = None) -> str:
    """Formats an Ethereum address into a canonical ERC-1056 DID string.

    Args:
        address: 20-byte Ethereum address (with or without 0x prefix).
        chain_id: Optional chain ID. If provided and not 1 (mainnet), prefix is included.

    Returns:
        Canonical ERC-1056 DID string (e.g. "did:ethr:0x1234...").
    """
    if not isinstance(address, str):
        raise ValueError("INVALID_ADDRESS: Address must be a string")

    addr_clean = address.strip()
    if not addr_clean.startswith("0x"):
        addr_clean = "0x" + addr_clean

    if not ETH_ADDRESS_REGEX.match(addr_clean):
        raise ValueError(f"INVALID_ADDRESS: '{address}' is not a valid 20-byte hex address")

    addr_lower = addr_clean.lower()
    if chain_id is not None and chain_id != 1:
        return f"did:ethr:{hex(chain_id)}:{addr_lower}"
    return f"did:ethr:{addr_lower}"


def parse_did(did: str) -> tuple[str, int | None]:
    """Parses an ERC-1056 DID string into (address_lowercase, chain_id_or_none).

    Args:
        did: ERC-1056 DID string.

    Returns:
        Tuple of (canonical_address_lower, chain_id_or_none).
    """
    if not isinstance(did, str):
        raise ValueError("INVALID_DID: DID must be a string")

    match = DID_ETHR_REGEX.match(did.strip())
    if not match:
        raise ValueError(f"INVALID_DID: '{did}' does not conform to ERC-1056 format")

    network_part, address_part = match.groups()
    chain_id: int | None = None
    if network_part:
        if network_part.startswith("0x") or network_part.startswith("0X"):
            chain_id = int(network_part, 16)
        elif network_part.isdigit():
            chain_id = int(network_part)

    return address_part.lower(), chain_id


def is_valid_did(did: str) -> bool:
    """Returns True if the string is a valid ERC-1056 DID, False otherwise."""
    if not isinstance(did, str):
        return False
    return bool(DID_ETHR_REGEX.match(did.strip()))


def resolve_did(did: str, default_chain_id: int = 31337) -> dict[str, Any]:
    """Generates a standard W3C DID Core 1.0 Document for an ERC-1056 DID.

    Args:
        did: Canonical ERC-1056 DID.
        default_chain_id: Default EIP-155 chain ID if not specified in DID.

    Returns:
        Dictionary representing W3C DID Document.
    """
    address_lower, parsed_chain_id = parse_did(did)
    chain_id = parsed_chain_id or default_chain_id

    # Canonical verification method identifier
    verification_method_id = f"{did}#controller"
    blockchain_account_id = f"eip155:{chain_id}:{address_lower}"

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": verification_method_id,
                "type": "EcdsaSecp256k1RecoveryMethod2020",
                "controller": did,
                "blockchainAccountId": blockchain_account_id,
            }
        ],
        "authentication": [verification_method_id],
        "assertionMethod": [verification_method_id],
    }
