"""High-Level Client for EvidenceRegistryDID Interaction.

Wraps JSON-RPC reads and cast.exe writes with ephemeral Anvil node context management.
Supports both live local/testnet node execution and deterministic mock mode for rapid testing.
"""
from __future__ import annotations

import json
import logging
import os
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from forensics.onchain import _run_cast, CAST_BIN, rpc_read, ALLOWED_CHAIN_IDS
from forensics.did.resolution import format_did
from forensics.did.eip712 import (
    build_custody_transfer_typed_data,
    build_attestation_typed_data,
    sign_typed_data,
    verify_typed_signature,
)

log = logging.getLogger("forensics.did.client")

# Default Anvil primary account
ANVIL_DEFAULT_DEPLOYER = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"


class AnvilTestNode:
    """Context manager spawning an isolated, ephemeral Anvil local blockchain node."""

    def __init__(self, port: int | None = None, chain_id: int = 31337):
        self.port = port or self._get_free_port()
        self.chain_id = chain_id
        self.proc: subprocess.Popen | None = None
        self.rpc_url = f"http://127.0.0.1:{self.port}"

    @staticmethod
    def _get_free_port() -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def __enter__(self) -> AnvilTestNode:
        root_dir = Path(__file__).resolve().parents[2]
        anvil_bin = root_dir / "tools" / "foundry" / "anvil.exe"
        if not anvil_bin.exists():
            anvil_bin = Path("anvil")

        cmd = [
            str(anvil_bin),
            "--port", str(self.port),
            "--chain-id", str(self.chain_id),
            "--disable-code-size-limit",
            "--silent",
        ]
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Poll readiness
        start = time.time()
        ready = False
        while time.time() - start < 5.0:
            try:
                rpc_read(self.rpc_url, "eth_chainId", [])
                ready = True
                break
            except Exception:
                time.sleep(0.1)

        if not ready:
            if self.proc:
                self.proc.terminate()
            raise RuntimeError(f"ANVIL_START_TIMEOUT: Node did not start on {self.rpc_url}")

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass


class DIDClient:
    """High-level client for EvidenceRegistryDID smart contract."""

    def __init__(
        self,
        rpc_url: str = "http://127.0.0.1:8545",
        contract_address: str | None = None,
        chain_id: int = 31337,
        mock_mode: bool = False,
    ):
        self.rpc_url = rpc_url
        self.contract_address = contract_address.lower() if contract_address else None
        self.chain_id = chain_id
        self.mock_mode = mock_mode
        self._mock_nonces: dict[str, int] = {}
        self._mock_roles: dict[tuple[str, str], bool] = {}
        self._mock_custody_history: list[dict[str, Any]] = []

    def deploy_registry(
        self,
        deployer_address: str = ANVIL_DEFAULT_DEPLOYER,
    ) -> str:
        """Deploys a fresh instance of EvidenceRegistryDID onto the target chain."""
        if self.mock_mode:
            self.contract_address = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
            return self.contract_address

        root_dir = Path(__file__).resolve().parents[2]
        forge_bin = root_dir / "tools" / "foundry" / "forge.exe"
        if not forge_bin.exists():
            forge_bin = Path("forge")

        contracts_root = root_dir / "contracts"

        cmd = [
            str(forge_bin), "create",
            "src/EvidenceRegistryDID.sol:EvidenceRegistryDID",
            "--root", str(contracts_root),
            "--rpc-url", self.rpc_url,
            "--unlocked",
            "--from", deployer_address,
            "--broadcast",
        ]

        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode != 0:
            raise RuntimeError(f"DEPLOYMENT_FAILED: {res.stderr or res.stdout}")

        deployed_address = None
        for line in res.stdout.splitlines():
            if "Deployed to:" in line:
                deployed_address = line.split("Deployed to:")[1].strip().lower()
                break

        if not deployed_address:
            raise RuntimeError(f"DEPLOYMENT_ADDRESS_NOT_FOUND: Output: {res.stdout}")

        self.contract_address = deployed_address
        return self.contract_address

    def _require_contract_address(self) -> str:
        if not self.contract_address:
            raise ValueError("CONTRACT_ADDRESS_REQUIRED: Deploy or specify contract_address first")
        return self.contract_address

    def get_did(self, address: str) -> str:
        """Returns the canonical ERC-1056 DID for an Ethereum address."""
        return format_did(address, chain_id=None)

    def get_owner(self) -> str:
        """Queries the contract owner address."""
        if self.mock_mode:
            return ANVIL_DEFAULT_DEPLOYER
        addr = self._require_contract_address()
        args = ["call", addr, "owner()(address)", "--rpc-url", self.rpc_url]
        res = _run_cast(args)
        return res.strip().lower()

    def has_role(self, account: str, role_bytes32: str) -> bool:
        """Queries whether account has been granted a specific forensic role."""
        if self.mock_mode:
            return self._mock_roles.get((account.lower(), role_bytes32.lower()), False)
        addr = self._require_contract_address()
        args = [
            "call", addr,
            "hasRole(address,bytes32)(bool)",
            account.lower(),
            role_bytes32.lower(),
            "--rpc-url", self.rpc_url,
        ]
        res = _run_cast(args)
        return res.strip().lower() in {"true", "1"}

    def has_forensic_role(self, account: str, role_bytes32: str) -> bool:
        """Queries whether account satisfies forensic role requirements."""
        if self.mock_mode:
            return self._mock_roles.get((account.lower(), role_bytes32.lower()), True)
        addr = self._require_contract_address()
        args = [
            "call", addr,
            "hasForensicRole(address,bytes32)(bool)",
            account.lower(),
            role_bytes32.lower(),
            "--rpc-url", self.rpc_url,
        ]
        res = _run_cast(args)
        return res.strip().lower() in {"true", "1"}

    def grant_role(
        self,
        account: str,
        role_bytes32: str,
        sender: str = ANVIL_DEFAULT_DEPLOYER,
    ) -> str:
        """Grants a forensic role to an account (onlyOwner)."""
        if self.mock_mode:
            self._mock_roles[(account.lower(), role_bytes32.lower())] = True
            return "0x" + "aa" * 32
        addr = self._require_contract_address()
        args = [
            "send", addr,
            "grantRole(address,bytes32)",
            account.lower(),
            role_bytes32.lower(),
            "--rpc-url", self.rpc_url,
            "--from", sender,
            "--unlocked",
        ]
        return _run_cast(args)

    def revoke_role(
        self,
        account: str,
        role_bytes32: str,
        sender: str = ANVIL_DEFAULT_DEPLOYER,
    ) -> str:
        """Revokes a forensic role from an account (onlyOwner)."""
        if self.mock_mode:
            self._mock_roles[(account.lower(), role_bytes32.lower())] = False
            return "0x" + "bb" * 32
        addr = self._require_contract_address()
        args = [
            "send", addr,
            "revokeRole(address,bytes32)",
            account.lower(),
            role_bytes32.lower(),
            "--rpc-url", self.rpc_url,
            "--from", sender,
            "--unlocked",
        ]
        return _run_cast(args)

    def get_nonce(self, account: str) -> int:
        """Queries the current anti-replay nonce for an account."""
        if self.mock_mode:
            return self._mock_nonces.get(account.lower(), 0)
        addr = self._require_contract_address()
        args = ["call", addr, "nonces(address)(uint256)", account.lower(), "--rpc-url", self.rpc_url]
        res = _run_cast(args)
        return int(res.strip())

    def transfer_custody_with_sig(
        self,
        evidence_id: int,
        from_custodian: str,
        to_custodian: str,
        artifact_sha256: str,
        note_hash: str,
        nonce: int,
        deadline: int,
        signature: str,
        sender: str = ANVIL_DEFAULT_DEPLOYER,
    ) -> str:
        """Submits an EIP-712 authenticated custody transfer."""
        if self.mock_mode:
            self._mock_nonces[from_custodian.lower()] = nonce + 1
            return "0x" + "cc" * 32
        addr = self._require_contract_address()
        args = [
            "send", addr,
            "transferCustodyWithSig(uint256,address,address,bytes32,bytes32,uint256,uint256,bytes)",
            str(evidence_id),
            from_custodian.lower(),
            to_custodian.lower(),
            artifact_sha256 if artifact_sha256.startswith("0x") else f"0x{artifact_sha256}",
            note_hash if note_hash.startswith("0x") else f"0x{note_hash}",
            str(nonce),
            str(deadline),
            signature,
            "--rpc-url", self.rpc_url,
            "--from", sender,
            "--unlocked",
        ]
        return _run_cast(args)

    def record_attestation_with_sig(
        self,
        evidence_id: int,
        attestor: str,
        role: str,
        artifact_hash: str,
        statement_hash: str,
        nonce: int,
        deadline: int,
        signature: str,
        sender: str = ANVIL_DEFAULT_DEPLOYER,
    ) -> str:
        """Submits an EIP-712 authenticated forensic attestation."""
        if self.mock_mode:
            self._mock_nonces[attestor.lower()] = nonce + 1
            return "0x" + "dd" * 32
        addr = self._require_contract_address()
        args = [
            "send", addr,
            "recordAttestationWithSig(uint256,address,bytes32,bytes32,bytes32,uint256,uint256,bytes)",
            str(evidence_id),
            attestor.lower(),
            role if role.startswith("0x") else f"0x{role}",
            artifact_hash if artifact_hash.startswith("0x") else f"0x{artifact_hash}",
            statement_hash if statement_hash.startswith("0x") else f"0x{statement_hash}",
            str(nonce),
            str(deadline),
            signature,
            "--rpc-url", self.rpc_url,
            "--from", sender,
            "--unlocked",
        ]
        return _run_cast(args)

    def anchor_forensic_evidence(
        self,
        evidence_id: int,
        model_hash: str,
        xai_digest: str,
        zkml_proof_hash: str,
        artifact_sha256: str,
        note_hash: str,
        sender: str = ANVIL_DEFAULT_DEPLOYER,
    ) -> str:
        """Anchors P8 ML, XAI, and P9 ZKML digests directly into custody history."""
        if self.mock_mode:
            return "0x" + "ee" * 32
        addr = self._require_contract_address()
        args = [
            "send", addr,
            "anchorForensicEvidence(uint256,bytes32,bytes32,bytes32,bytes32,bytes32)",
            str(evidence_id),
            model_hash if model_hash.startswith("0x") else f"0x{model_hash}",
            xai_digest if xai_digest.startswith("0x") else f"0x{xai_digest}",
            zkml_proof_hash if zkml_proof_hash.startswith("0x") else f"0x{zkml_proof_hash}",
            artifact_sha256 if artifact_sha256.startswith("0x") else f"0x{artifact_sha256}",
            note_hash if note_hash.startswith("0x") else f"0x{note_hash}",
            "--rpc-url", self.rpc_url,
            "--from", sender,
            "--unlocked",
        ]
        return _run_cast(args)

    def get_custody_count_did(self, evidence_id: int) -> int:
        """Queries total number of rich DID custody records for an evidenceId."""
        if self.mock_mode:
            return len(self._mock_custody_history)
        addr = self._require_contract_address()
        args = ["call", addr, "getCustodyCountDID(uint256)(uint256)", str(evidence_id), "--rpc-url", self.rpc_url]
        res = _run_cast(args)
        return int(res.strip())
