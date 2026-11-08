"""Adversarial Empirical Challenge Test Suite for Milestone 3 (R4).

Written by Empirical Challenger to independently and adversarially stress-test:
1. SSRF Fuzzing Vectors:
   - 10.0.0.1, 192.168.1.1, 172.16.0.1, 127.0.0.1 (allow_local=False)
   - 127.1 (abbreviated loopback)
   - 2130706433 (decimal integer loopback)
   - 0x7f000001 (hex integer loopback)
   - 0177.0.0.1 (octal loopback)
   - 169.254.169.254 (AWS/GCP/Azure IMDS)
   - [::1] (IPv6 loopback)
   - [fd00:ec2::254] (AWS IPv6 IMDS)
   - Rejection in both validate_rpc_url and FastAPI POST /api/rpc/preflight.
2. HTTP Redirect Evasion:
   - 301, 302, 303, 307, 308 redirect attacks pointing to private/metadata targets.
   - Verified that _NoRedirectHandler and safe_rpc_call strictly abort with SSRFSecurityError.
3. Non-allowlisted RPC URLs:
   - https://evil-attacker-node.xyz/rpc
   - https://attacker.com/eth
   - Strict rejection with RpcAllowlistError / 403.
4. State-altering JSON-RPC methods:
   - eth_sendTransaction, eth_sendRawTransaction, personal_sign, eth_sign, eth_signTransaction, wallet_sendCalls, personal_unlockAccount.
   - Strict rejection with ReadOnlyViolationError.
5. Bounded block querying:
   - Requesting 10,000 blocks is auto-bounded to safe limit (<= 500 blocks, max_blocks capped).
6. Address search guardrails:
   - Explains JSON-RPC limitations, never fabricates fake transactions.
7. Storage isolation & Canonical DB Invariance:
   - 100% bitwise SHA-256 match for real_p4.db, forensics.db, benchmark_p6.db, endpoint_evidence.db.
"""

from __future__ import annotations

import hashlib
import http.server
import json
from pathlib import Path
import threading
from typing import Any, Dict, List
import pytest
from fastapi.testclient import TestClient

from dashboard.app import app
from forensics.paths import (
    get_benchmark_db,
    get_endpoint_evidence_db,
    get_forensics_db,
    get_real_p4_db,
)
from forensics.rpc_guard import (
    ReadOnlyViolationError,
    RpcAllowlistError,
    SSRFSecurityError,
    assert_read_only_method,
    check_ssrf_safety,
    safe_rpc_call,
    validate_rpc_url,
)
from forensics.live_collector import (
    LiveInvestigationRequest,
    LiveRpcCollector,
    MAX_BLOCKS_LIMIT,
)


def _file_sha256(path: Path) -> str:
    """Computes SHA-256 of file."""
    if not path.is_file():
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()


# ------------------------------------------------------------------------------
# Mock Servers for Redirect and JSON-RPC
# ------------------------------------------------------------------------------

class MultiRedirectHandler(http.server.BaseHTTPRequestHandler):
    """Server that issues different HTTP redirect status codes (301, 302, 303, 307, 308)."""
    target_location = "http://169.254.169.254/latest/meta-data/"
    status_code_to_return = 302

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            self.rfile.read(length)
        self.send_response(self.status_code_to_return)
        self.send_header("Location", self.target_location)
        self.send_header("Content-Length", "0")
        self.end_headers()


class ChallengerRpcHandler(http.server.BaseHTTPRequestHandler):
    """Local JSON-RPC handler for adversarial testing."""
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length).decode("utf-8")
        req = json.loads(data)
        method = req.get("method")
        req_id = req.get("id", 1)

        result: Any = None
        if method == "eth_chainId":
            result = "0x1"
        elif method == "eth_blockNumber":
            result = "0x1000"  # 4096
        elif method == "eth_getBlockByNumber":
            result = {
                "number": "0x1000",
                "hash": "0x" + "a" * 64,
                "parentHash": "0x" + "b" * 64,
                "timestamp": "0x66000000",
                "gasUsed": "0x5208",
                "transactions": [],
            }
        elif method == "eth_getLogs":
            result = []

        res = {"jsonrpc": "2.0", "id": req_id, "result": result}
        body = json.dumps(res).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ------------------------------------------------------------------------------
# 1. Adversarial SSRF Fuzzing
# ------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw_ip",
    [
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "127.0.0.1",
        "127.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "169.254.169.254",
        "[::1]",
        "[fd00:ec2::254]",
    ],
)
def test_ssrf_raw_ip_fuzzing_check(raw_ip: str):
    """Verifies that check_ssrf_safety blocks all adversarial SSRF IP formats without allow_local."""
    is_safe = check_ssrf_safety(raw_ip, allow_local=False)
    assert is_safe is False, f"IP format '{raw_ip}' was unexpectedly marked safe without allow_local!"


@pytest.mark.parametrize(
    "url_target",
    [
        "http://10.0.0.1:8545",
        "http://192.168.1.1:8545",
        "http://172.16.0.1:8545",
        "http://127.0.0.1:8545",
        "http://127.1:8545",
        "http://2130706433:8545",
        "http://0x7f000001:8545",
        "http://0177.0.0.1:8545",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]:8545",
        "http://[fd00:ec2::254]:8545",
    ],
)
def test_validate_rpc_url_ssrf_rejection(url_target: str):
    """Verifies validate_rpc_url strictly rejects all SSRF URL vectors."""
    # Boolean return mode
    assert validate_rpc_url(url_target, allow_local=False, raise_on_error=False) is False

    # Exception mode
    with pytest.raises((SSRFSecurityError, RpcAllowlistError, ValueError)):
        validate_rpc_url(url_target, allow_local=False, raise_on_error=True)


@pytest.mark.parametrize(
    "url_target",
    [
        "http://10.0.0.1:8545",
        "http://192.168.1.1:8545",
        "http://172.16.0.1:8545",
        "http://127.0.0.1:8545",
        "http://127.1:8545",
        "http://2130706433:8545",
        "http://0x7f000001:8545",
        "http://0177.0.0.1:8545",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]:8545",
        "http://[fd00:ec2::254]:8545",
        "https://evil-attacker-node.xyz/rpc",
    ],
)
def test_api_preflight_ssrf_and_allowlist_fuzzing(url_target: str):
    """Verifies POST /api/rpc/preflight returns 422 or 403 for all adversarial vectors."""
    client = TestClient(app)
    res = client.post("/api/rpc/preflight", json={"rpc_url": url_target, "allow_local": False})
    assert res.status_code in (422, 403), f"Endpoint {url_target} returned unexpected status {res.status_code}"


# ------------------------------------------------------------------------------
# 2. HTTP Redirect Evasion (301, 302, 303, 307, 308)
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("redirect_code", [301, 302, 303, 307, 308])
def test_http_redirect_evasion_blocked(redirect_code: int):
    """Verifies _NoRedirectHandler blocks 301, 302, 303, 307, 308 redirects pointing to internal targets."""
    server = http.server.HTTPServer(("127.0.0.1", 0), MultiRedirectHandler)
    server.RequestHandlerClass.status_code_to_return = redirect_code
    server.RequestHandlerClass.target_location = "http://169.254.169.254/latest/meta-data/"
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    redirect_url = f"http://127.0.0.1:{port}"
    try:
        with pytest.raises(SSRFSecurityError) as exc_info:
            safe_rpc_call(
                rpc_url=redirect_url,
                method="eth_chainId",
                allow_local=True,  # allow connection to redirect server, but redirect itself must be rejected
                timeout=5,
            )
        err_msg = str(exc_info.value).lower()
        assert "chuyển hướng http" in err_msg or "ssrf" in err_msg or str(redirect_code) in err_msg
    finally:
        server.shutdown()


# ------------------------------------------------------------------------------
# 3. Non-Allowlisted RPC URLs
# ------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "evil_url",
    [
        "https://evil-attacker-node.xyz/rpc",
        "https://attacker.evil.com/jsonrpc",
        "https://phishing-sepolia.net/rpc",
        "https://not-in-allowlist.org",
    ],
)
def test_non_allowlisted_rpc_urls_rejected(evil_url: str):
    """Verifies strict rejection of non-allowlisted RPC URLs."""
    with pytest.raises(RpcAllowlistError):
        validate_rpc_url(evil_url, raise_on_error=True)

    client = TestClient(app)
    res = client.post("/api/rpc/preflight", json={"rpc_url": evil_url, "allow_local": False})
    assert res.status_code == 403


# ------------------------------------------------------------------------------
# 4. State-Altering JSON-RPC Methods Rejection
# ------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "forbidden_method",
    [
        "eth_sendTransaction",
        "eth_sendRawTransaction",
        "personal_sign",
        "personal_sendTransaction",
        "eth_sign",
        "eth_signTransaction",
        "eth_signTypedData",
        "eth_signTypedData_v4",
        "wallet_sendCalls",
        "personal_unlockAccount",
        "personal_newAccount",
        "admin_nodeInfo",
        "miner_start",
    ],
)
def test_state_altering_methods_rejected(forbidden_method: str):
    """Verifies that asserting state-altering methods raises ReadOnlyViolationError."""
    with pytest.raises(ReadOnlyViolationError):
        assert_read_only_method(forbidden_method)


# ------------------------------------------------------------------------------
# 5. Bounded Block Querying Verification
# ------------------------------------------------------------------------------

def test_bounded_block_query_capping(tmp_path: Path):
    """Verifies that an adversary requesting 10,000 blocks is strictly capped to MAX_BLOCKS_LIMIT / max_blocks."""
    server = http.server.HTTPServer(("127.0.0.1", 0), ChallengerRpcHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    mock_url = f"http://127.0.0.1:{port}"

    try:
        collector = LiveRpcCollector(data_dir=tmp_path / "data", output_dir=tmp_path / "reports")
        # Adversary attempts to request 10,000 blocks
        huge_range = (1, 10000)
        req = LiveInvestigationRequest(
            case_id="case-adversarial-blocks",
            rpc_url=mock_url,
            block_range=huge_range,
            max_blocks=10000,  # adversarial excessive limit
            limit_requests=20,
            allow_local=True,
        )

        res = collector.collect_and_investigate(req)
        # Verify the actual span collected was capped to <= MAX_BLOCKS_LIMIT (500)
        actual_span = res.end_block - res.start_block + 1
        assert actual_span <= MAX_BLOCKS_LIMIT, f"Block span {actual_span} exceeded MAX_BLOCKS_LIMIT {MAX_BLOCKS_LIMIT}!"
        assert res.blocks_collected <= 20  # bounded by limit_requests
    finally:
        server.shutdown()


# ------------------------------------------------------------------------------
# 6. Address Search Guardrail Verification
# ------------------------------------------------------------------------------

def test_address_search_guardrail_protocol_limits(tmp_path: Path):
    """Verifies that querying an arbitrary address documents protocol limits and never fabricates transactions."""
    server = http.server.HTTPServer(("127.0.0.1", 0), ChallengerRpcHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    mock_url = f"http://127.0.0.1:{port}"

    try:
        collector = LiveRpcCollector(data_dir=tmp_path / "data", output_dir=tmp_path / "reports")
        unknown_target = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        req = LiveInvestigationRequest(
            case_id="case-guardrail-audit",
            rpc_url=mock_url,
            addresses=[unknown_target],
            block_range=(4090, 4096),
            allow_local=True,
        )

        res = collector.collect_and_investigate(req)
        # Guardrail notes must be present
        assert len(res.address_guardrail_notes) > 0
        note = res.address_guardrail_notes[0].lower()
        # Must explicitly note full node indexing limits
        assert "chỉ mục địa chỉ" in note or "address indexer" in note or "json-rpc" in note
        # Must affirm no fake / fabricated data
        assert "giả lập" in note or "không tạo" in note
        # When no txs match, transactions_collected must be 0, not fabricated
        assert res.transactions_collected == 0
    finally:
        server.shutdown()


# ------------------------------------------------------------------------------
# 7. Canonical Database 100% SHA-256 Invariance
# ------------------------------------------------------------------------------

def test_storage_isolation_and_canonical_db_invariance(tmp_path: Path):
    """Verifies that all live RPC investigation activities maintain 100% bitwise invariance of the 4 canonical databases."""
    canonical_dbs = {
        "real_p4.db": get_real_p4_db(),
        "forensics.db": get_forensics_db(),
        "benchmark_p6.db": get_benchmark_db(),
        "endpoint_evidence.db": get_endpoint_evidence_db(),
    }

    # 1. Compute initial SHA-256 hashes
    initial_hashes = {}
    for name, db_path in canonical_dbs.items():
        if db_path.is_file():
            initial_hashes[name] = _file_sha256(db_path)
            assert len(initial_hashes[name]) == 64

    # 2. Run mock server and perform live investigation
    server = http.server.HTTPServer(("127.0.0.1", 0), ChallengerRpcHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    mock_url = f"http://127.0.0.1:{port}"

    try:
        collector = LiveRpcCollector(data_dir=tmp_path / "data", output_dir=tmp_path / "reports")
        req = LiveInvestigationRequest(
            case_id="case-db-invariance-stress",
            rpc_url=mock_url,
            block_range=(4090, 4095),
            allow_local=True,
        )
        res = collector.collect_and_investigate(req)
        assert res.status == "completed"

        # 3. Re-verify SHA-256 hashes of all canonical databases
        for name, db_path in canonical_dbs.items():
            if db_path.is_file():
                current_hash = _file_sha256(db_path)
                assert current_hash == initial_hashes[name], (
                    f"CRITICAL SECURITY VIOLATION: Database {name} modified during RPC investigation!\n"
                    f"Before: {initial_hashes[name]}\n"
                    f"After:  {current_hash}"
                )
    finally:
        server.shutdown()
