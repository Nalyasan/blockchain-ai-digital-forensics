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

    def register_evidence(
        self,
        case_id_bytes32: str,
        manifest_sha256: str,
        storage_uri: str,
        sender: str = ANVIL_DEFAULT_DEPLOYER,
    ) -> int:
        """Registers a new evidence package on-chain and returns the evidenceId."""
        if self.mock_mode:
            mock_id = len(self._mock_custody_history) + 1
            return mock_id

        addr = self._require_contract_address()

        # Format case_id to 32 bytes
        c_id = case_id_bytes32.strip()
        if not c_id.startswith("0x") and not c_id.startswith("0X"):
            if len(c_id) == 64 and re.fullmatch(r"^[a-fA-F0-9]{64}$", c_id):
                c_id = f"0x{c_id}"
            else:
                c_id = "0x" + hashlib.sha256(c_id.encode("utf-8")).hexdigest()

        m_hash = manifest_sha256.strip()
        if not m_hash.startswith("0x") and not m_hash.startswith("0X"):
            m_hash = f"0x{m_hash}"

        uri = storage_uri.strip()
        if not uri.startswith("evidence://"):
            uri = f"evidence://{uri}"

        args = [
            "send", addr,
            "registerEvidence(bytes32,bytes32,string)(uint256)",
            c_id,
            m_hash,
            uri,
            "--rpc-url", self.rpc_url,
            "--from", sender,
            "--unlocked",
        ]
        _run_cast(args)

        # Query nextEvidenceId - 1
        res = _run_cast(["call", addr, "nextEvidenceId()(uint256)", "--rpc-url", self.rpc_url])
        return int(res.strip()) - 1

    def get_evidence(self, evidence_id: int) -> dict[str, Any]:
        """Queries on-chain evidence details for an evidenceId."""
        if self.mock_mode:
            return {
                "evidence_id": evidence_id,
                "case_id": "0x" + "11" * 32,
                "manifest_sha256": "0x" + "22" * 32,
                "registered_by": ANVIL_DEFAULT_DEPLOYER,
                "timestamp": int(time.time()),
                "storage_uri": f"evidence://case-{evidence_id}/manifest.json",
                "exists": True,
            }

        addr = self._require_contract_address()
        args = ["call", addr, "getEvidence(uint256)", str(evidence_id), "--rpc-url", self.rpc_url]
        res = _run_cast(args)
        lines = [line.strip() for line in res.splitlines() if line.strip()]
        result: dict[str, Any] = {
            "evidence_id": evidence_id,
            "raw_output": lines,
            "exists": True,
        }
        if len(lines) >= 6:
            result["case_id"] = lines[0]
            result["manifest_sha256"] = lines[1]
            result["registered_by"] = lines[2].lower()
            try:
                result["timestamp"] = int(lines[3])
            except (ValueError, TypeError):
                result["timestamp"] = lines[3]
            result["storage_uri"] = lines[4].strip('"')
            result["exists"] = lines[5].lower() == "true"
        return result

    def get_custody_history_did(self, evidence_id: int) -> list[dict[str, Any]]:
        """Queries the full W3C DID chain of custody records for an evidenceId."""
        if self.mock_mode:
            return self._mock_custody_history

        addr = self._require_contract_address()
        args = [
            "call", addr,
            "getCustodyHistoryDID(uint256)",
            str(evidence_id),
            "--rpc-url", self.rpc_url,
        ]
        res = _run_cast(args)
        raw_lines = [line.strip() for line in res.splitlines() if line.strip()]
        records: list[dict[str, Any]] = [{
            "evidence_id": evidence_id,
            "raw_lines": raw_lines,
        }]
        return records

    def transfer_custody_with_sig_receipt(
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
    ) -> dict[str, Any]:
        """Submits an EIP-712 authenticated custody transfer and returns full JSON receipt."""
        if self.mock_mode:
            self._mock_nonces[from_custodian.lower()] = nonce + 1
            return {
                "transaction_hash": f"0x{'11'*32} (synthetic)",
                "block_number": 1,
                "gas_used": 142500,
                "status": 1,
                "is_synthetic": True,
            }

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
            "--json",
        ]
        res_json = _run_cast(args)
        try:
            receipt = json.loads(res_json)
        except json.JSONDecodeError:
            receipt = {}

        tx_hash = receipt.get("transactionHash", "")
        bn_raw = receipt.get("blockNumber", "0x0")
        gu_raw = receipt.get("gasUsed", "0x0")
        st_raw = receipt.get("status", "0x1")

        block_num = int(bn_raw, 16) if isinstance(bn_raw, str) and bn_raw.startswith("0x") else int(bn_raw or 0)
        gas_used = int(gu_raw, 16) if isinstance(gu_raw, str) and gu_raw.startswith("0x") else int(gu_raw or 0)
        status_num = int(st_raw, 16) if isinstance(st_raw, str) and st_raw.startswith("0x") else int(st_raw or 1)

        return {
            "transaction_hash": f"{tx_hash} (synthetic)",
            "block_number": block_num,
            "gas_used": gas_used,
            "status": status_num,
            "is_synthetic": True,
        }

