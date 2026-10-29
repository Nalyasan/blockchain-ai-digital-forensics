"""Module tương tác On-chain với EvidenceRegistry.sol (Mục 6.5 & P3).
Đảm bảo:
1. subprocess với shell=False, timeout=30s, đối số danh sách cố định.
2. Không truyền private key qua đối số dòng lệnh (dùng cast keystore / unlocked account).
3. Chốt chặn an toàn khóa (Key Safety Guard): chặn tài khoản mặc định Anvil trên chain khác 31337.
4. Cơ chế --from / --unlocked CHỈ được phép trên chuỗi Anvil (chain_id == 31337). Trên chain khác, bắt buộc dùng keystore (--account).
5. Đối soát chain_id giữa RPC và ANCHOR_CHAIN_ID; chỉ cho phép allowlist [31337, 11155111].
6. Giải mã event EvidenceRegistered từ receipt: kiểm tra status=1, đủ 4 topics, khớp caseId và manifestSha256.
7. Kiểm tra trạng thái Git working tree cả từ manifest và động tại thời điểm anchor; ghi nhận bền vững vào SQLite khi dùng --allow-dirty.
"""
import os
import re
import sys
import json
import logging
import sqlite3
import subprocess
import urllib.request
import urllib.parse
from datetime import datetime, timezone

from forensics.schemas import init_db
from forensics.evidence import is_working_tree_dirty, compute_file_sha256

log = logging.getLogger("forensics.onchain")

# Topic 0 của các event trong EvidenceRegistry.sol
TOPIC_EVIDENCE_REGISTERED = "0xb8860d0b7752b79a5877f967e02eea9de30085e65c13774df90c674fcf4a6e58"
TOPIC_CUSTODY_RECORDED = "0xcf6b2d07eec198ac5313cb4e7be0d697c16d152be5eb56184111da1ee211a31b"

# Danh sách chain_id cho phép (Anvil & Sepolia)
ALLOWED_CHAIN_IDS = {31337, 11155111}

# Đường dẫn tới công cụ cast
CAST_BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "foundry", "cast.exe")
if not os.path.exists(CAST_BIN):
    CAST_BIN = "cast"

def safe_redact_error(msg: str) -> str:
    """Do not expose untrusted tool output; secrets need not have a known format."""
    return "CAST_ERROR: công cụ không hoàn tất yêu cầu"

def normalize_address(address: str) -> str:
    if not isinstance(address, str) or not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{40}", address):
        raise ValueError("INVALID_ADDRESS: địa chỉ phải có 20 byte hex")
    return "0x" + address[-40:].lower()

def validate_rpc_url(url: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(url)
        valid = parsed.scheme in {"http", "https"} and bool(parsed.hostname)
        valid = valid and not any(c.isspace() or ord(c) < 32 for c in url)
        valid = valid and not parsed.fragment
        _ = parsed.port
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ValueError("RPC_URL_INVALID: chỉ cho phép URL http/https hợp lệ")
    if not is_loopback_rpc(url) and parsed.scheme != "https":
        raise ValueError("RPC_TLS_REQUIRED: endpoint ngoài loopback phải dùng https")

class _NoRpcRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("RPC_REDIRECT_REJECTED")

def rpc_read(rpc_url: str, method: str, params: list):
    validate_rpc_url(rpc_url)
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode("utf-8")
    try:
        req = urllib.request.Request(rpc_url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.build_opener(_NoRpcRedirect()).open(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        if not isinstance(result, dict) or "error" in result or "result" not in result:
            raise ValueError()
        return result["result"]
    except Exception:
        raise RuntimeError("RPC_QUERY_FAILED: không nhận được kết quả RPC hợp lệ") from None

def _run_cast(args: list[str], timeout: int = 30) -> str:
    # Prevent inherited wallet settings from selecting a different signer.
    env = {k: v for k, v in os.environ.items() if not (
        k.upper().startswith(("ETH_", "TEMPO_")) or k.upper() in {"PRIVATE_KEY", "CHAIN"}
    )}
    try:
        res = subprocess.run([CAST_BIN] + args, capture_output=True, text=True,
                             shell=False, timeout=timeout, check=False, env=env)
    except subprocess.TimeoutExpired:
        raise RuntimeError("CAST_TIMEOUT: hết thời gian; trạng thái giao dịch chưa xác định") from None
    except Exception:
        raise RuntimeError("CAST_EXEC_FAILED: không thể chạy công cụ") from None
    if res.returncode != 0:
        raise RuntimeError(f"CAST_EXIT_{int(res.returncode)}: công cụ không hoàn tất yêu cầu")
    return res.stdout.strip()

def get_rpc_chain_id(rpc_url: str) -> int:
    """Truy vấn eth_chainId từ RPC nguồn."""
    val = rpc_read(rpc_url, "eth_chainId", [])
    try:
        return int(val, 16) if isinstance(val, str) and val.startswith("0x") else int(val)
    except (ValueError, TypeError):
        raise RuntimeError("RPC_CHAIN_INVALID: chain_id không hợp lệ") from None

def compute_anvil_default_accounts() -> list[str]:
    """Tính toán 10 địa chỉ mặc định của Anvil tại runtime từ mnemonic chuẩn."""
    accounts = []
    try:
        for i in range(10):
            address = _run_cast(
                ["wallet", "address", "--mnemonic",
                 "test test test test test test test test test test test junk",
                 "--mnemonic-index", str(i)],
                timeout=5
            )
            accounts.append(normalize_address(address))
    except Exception:
        raise RuntimeError("ANVIL_ACCOUNTS_UNAVAILABLE: không tính được đủ 10 địa chỉ; từ chối ký") from None
    if len(set(accounts)) != 10:
        raise RuntimeError("ANVIL_ACCOUNTS_UNAVAILABLE: địa chỉ không duy nhất; từ chối ký")
    return accounts

def is_loopback_rpc(rpc_url: str) -> bool:
    """Xác định URL của RPC endpoint có trỏ về loopback cục bộ hay không.
    Chấp nhận: 127.0.0.1, localhost, [::1], ::1.
    Từ chối bất kỳ domain từ xa hoặc IP mạng ngoài nào.
    """
    try:
        parsed = urllib.parse.urlparse(rpc_url)
        hostname = (parsed.hostname or "").lower().strip()
        hostname = hostname.strip("[]")
        return hostname in {"127.0.0.1", "localhost", "::1"}
    except Exception:
        return False

def validate_chain_and_guard(
    signer_address: str,
    rpc_url: str = None,
    is_write: bool = False
) -> int:
    """Validate the RPC chain and the resolved signer; no chain override exists."""
    url = rpc_url or os.environ.get("ANCHOR_RPC_URL", "http://127.0.0.1:8545")
    validate_rpc_url(url)
    signer = normalize_address(signer_address)
    rpc_chain_id = get_rpc_chain_id(url)
    env_chain = os.environ.get("ANCHOR_CHAIN_ID")
    if env_chain and env_chain.strip():
        try:
            configured_chain = int(env_chain.strip())
        except ValueError:
            raise ValueError("CHAIN_CONFIG_INVALID: chain_id cấu hình không hợp lệ") from None
        if configured_chain != rpc_chain_id:
            raise ValueError("Chain ID mismatch: RPC khác cấu hình ANCHOR_CHAIN_ID")
    if rpc_chain_id not in ALLOWED_CHAIN_IDS:
        prefix = "Chốt chặn an toàn ghi: " if is_write else ""
        raise ValueError(prefix + "Chain ID không nằm trong danh sách cho phép")
    if rpc_chain_id != 31337 and signer in compute_anvil_default_accounts():
        raise ValueError("Chặn khóa mặc định Anvil: từ chối người ký trên chain khác 31337")
    return rpc_chain_id


def resolve_signer(account: str = None, password_file: str = None, from_addr: str = None) -> str:
    declared = from_addr or os.environ.get("ANCHOR_FROM")
    if account:
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", account):
            raise ValueError("ACCOUNT_INVALID: tên keystore không hợp lệ")
        args = ["wallet", "address", "--account", account]
        if password_file:
            args.extend(["--password-file", password_file])
        signer = normalize_address(_run_cast(args))
        if declared and normalize_address(declared) != signer:
            raise ValueError("SIGNER_MISMATCH: --from/ANCHOR_FROM khác địa chỉ keystore")
        return signer
    return normalize_address(declared or "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")


def prepare_write(contract_address, url, account, password_file, from_addr):
    validate_rpc_url(url)
    signer = resolve_signer(account, password_file, from_addr)
    chain_id = validate_chain_and_guard(signer, rpc_url=url, is_write=True)
    if not account:
        if chain_id != 31337:
            raise ValueError("Trên mạng không phải Anvil, bắt buộc sử dụng keystore với đối số --account")
        if not is_loopback_rpc(url):
            raise ValueError("Chế độ ký --unlocked CHỈ được phép trên RPC cục bộ loopback")
        client = rpc_read(url, "web3_clientVersion", [])
        if not isinstance(client, str) or not re.match(r"(?i)^anvil(?:[/ -]|$)", client):
            raise ValueError("ANVIL_CLIENT_REQUIRED: --unlocked yêu cầu client Anvil")
    code = rpc_read(url, "eth_getCode", [contract_address, "latest"])
    if not isinstance(code, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})+", code):
        raise ValueError("CONTRACT_CODE_MISSING: contract không có bytecode hợp lệ")
    return signer, chain_id


def receipt_signer(receipt, expected_signer):
    if not isinstance(receipt, dict):
        raise RuntimeError("RECEIPT_UNAVAILABLE: chưa nhận được receipt")
    actor = normalize_address(receipt.get("from"))
    if actor != expected_signer:
        raise ValueError("RECEIPT_SIGNER_MISMATCH: người gửi receipt khác signer đã kiểm tra")
    return actor

def verify_manifest_ready_for_anchor(manifest_data: dict, allow_dirty: bool = False) -> str:
    """Kiểm tra điều kiện manifest và git working tree trước khi neo on-chain:
    Kiểm tra cả trường working_tree_dirty trong manifest VÀ kiểm tra Git động tại thời điểm neo.
    Từ chối nếu có bất kỳ thay đổi chưa commit nào trừ khi có cờ allow_dirty.
    """
    manifest_dirty = bool(manifest_data.get("software", {}).get("working_tree_dirty", False))
    dynamic_dirty = is_working_tree_dirty()

    if manifest_dirty or dynamic_dirty:
        reasons = []
        if manifest_dirty:
            reasons.append("manifest ghi nhận working_tree_dirty=True lúc xuất gói")
        if dynamic_dirty:
            reasons.append("git working tree có thay đổi chưa commit lúc anchor")
        reasons_desc = "; ".join(reasons)

        if not allow_dirty:
            raise ValueError(
                f"Phát hiện trạng thái working tree chưa sạch ({reasons_desc}). "
                "Cần commit git trước khi anchor hoặc sử dụng cờ --allow-dirty để ghi nhận ngoại lệ."
            )
        return f"ALLOW_DIRTY_WARNING: Gói chứng cứ được neo khi git tree chưa sạch ({reasons_desc})"
    return "CLEAN_TREE"

def extract_evidence_id_from_receipt(
    receipt: dict,
    expected_case_id: str = None,
    expected_manifest_sha256: str = None
) -> int:
    """Giải mã event EvidenceRegistered trong receipt để lấy chính xác evidenceId.
    Kiểm tra:
    1. Giao dịch thành công (status == 1).
    2. Event tồn tại và đủ 4 topics (topic0, topic1=evidenceId, topic2=caseId, topic3=manifestSha256).
    3. Đối soát caseId và manifestSha256 nếu được truyền vào.
    """
    status = receipt.get("status")
    if status not in (1, "0x1", "1"):
        raise RuntimeError(f"Giao dịch on-chain thất bại (receipt status={status})")

    logs = receipt.get("logs", [])
    for lg in logs:
        topics = lg.get("topics", [])
        if topics and topics[0].lower() == TOPIC_EVIDENCE_REGISTERED.lower():
            if len(topics) < 4:
                raise ValueError(
                    f"Event EvidenceRegistered không hợp lệ hoặc thiếu indexed topics (yêu cầu 4 topics, nhận {len(topics)})"
                )
            evidence_id = int(topics[1], 16)
            if expected_case_id:
                exp_case_b32 = string_to_bytes32_hex(expected_case_id).lower()
                if topics[2].lower() != exp_case_b32:
                    raise ValueError(f"Event caseId mismatch: mong muốn {exp_case_b32}, nhận {topics[2]}")
            if expected_manifest_sha256:
                exp_hash_b32 = ("0x" + expected_manifest_sha256 if not expected_manifest_sha256.startswith("0x") else expected_manifest_sha256).lower()
                if topics[3].lower() != exp_hash_b32:
                    raise ValueError(f"Event manifestSha256 mismatch: mong muốn {exp_hash_b32}, nhận {topics[3]}")
            return evidence_id

    raise ValueError("Không tìm thấy event EvidenceRegistered hợp lệ trong receipt của giao dịch!")

def string_to_bytes32_hex(text: str) -> str:
    """Chuyển đổi chuỗi sang bytes32 định dạng 0x hex có padding."""
    b = text.encode("utf-8")
    if len(b) > 32:
        raise ValueError(f"Chuỗi '{text}' vượt quá 32 bytes ({len(b)} bytes)")
    return "0x" + b.ljust(32, b"\0").hex()

def run_cast_send(args: list[str]) -> str:
    return _run_cast(["send"] + args)


def run_cast_call(args: list[str]) -> str:
    return _run_cast(["call"] + args)


def get_transaction_receipt(tx_hash: str, rpc_url: str) -> dict:
    return rpc_read(rpc_url, "eth_getTransactionReceipt", [tx_hash])

def anchor_evidence(
    manifest_path_or_dir: str,
    contract_address: str,
    db_path: str = None,
    account: str = None,
    password_file: str = None,
    from_addr: str = None,
    allow_dirty: bool = False,
    rpc_url: str = None
) -> dict:
    """Neo gói chứng cứ lên blockchain qua EvidenceRegistry.sol.
    1. Xác minh toàn vẹn gói chứng cứ trên đĩa.
    2. Kiểm tra chốt chặn an toàn (working_tree_dirty cả manifest và git động, chain_id, Key Safety Guard).
    3. Ràng buộc: trên mạng non-Anvil, bắt buộc dùng keystore (--account).
    4. Gửi transaction registerEvidence(bytes32,bytes32,string).
    5. Giải mã receipt trích xuất evidenceId (đủ 4 topics), cập nhật evidence_exports, custody_events và audit_events.
    """
    if not re.match(r"^0x[0-9a-fA-F]{40}$", contract_address):
        raise ValueError(f"Địa chỉ contract không hợp lệ: {contract_address}")

    # 1. Đọc và xác minh manifest
    manifest_file = os.path.join(manifest_path_or_dir, "manifest.json") if os.path.isdir(manifest_path_or_dir) else manifest_path_or_dir
    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)

    # 2. Kiểm tra working_tree_dirty (manifest + git động)
    dirty_note = verify_manifest_ready_for_anchor(manifest_data, allow_dirty=allow_dirty)

    # 3. Tính toán SHA-256 của manifest
    manifest_sha256 = compute_file_sha256(manifest_file)
    case_id = manifest_data["case_id"]

    url = rpc_url or os.environ.get("ANCHOR_RPC_URL", "http://127.0.0.1:8545")
    signer, chain_id = prepare_write(contract_address, url, account, password_file, from_addr)

    case_id_b32 = string_to_bytes32_hex(case_id)
    manifest_hash_b32 = "0x" + manifest_sha256
    storage_uri = f"evidence://{case_id}/manifest.json".strip()
    if not storage_uri:
        raise ValueError("storage_uri không được để trống!")
    if len(storage_uri.encode("utf-8")) > 256:
        raise ValueError(f"storage_uri vượt quá 256 bytes ({len(storage_uri.encode('utf-8'))} bytes)")

    # Chuẩn bị đối số cho cast send
    # Không truyền private-key qua CLI! Dùng --account + --password-file hoặc --from + unlocked (chỉ Anvil)
    cast_args = [
        contract_address,
        "registerEvidence(bytes32,bytes32,string)",
        case_id_b32,
        manifest_hash_b32,
        storage_uri,
        "--rpc-url", url,
        "--chain", str(chain_id),
        "--json"
    ]
    if account:
        cast_args.extend(["--account", account])
        if password_file:
            cast_args.extend(["--password-file", password_file])
    else:
        cast_args.extend(["--from", signer, "--unlocked"])

    log.info("Đang neo chứng cứ case_id=%s, manifest_sha256=%s lên contract %s...", case_id, manifest_sha256, contract_address)
    send_out = run_cast_send(cast_args)

    try:
        tx_data = json.loads(send_out)
        tx_hash = tx_data.get("transactionHash") or tx_data.get("hash")
    except Exception:
        m = re.search(r"0x[0-9a-fA-F]{64}", send_out)
        tx_hash = m.group(0) if m else None

    if not isinstance(tx_hash, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash):
        raise RuntimeError("CAST_RESPONSE_INVALID: không nhận được transaction hash")

    receipt = get_transaction_receipt(tx_hash, url)
    actor = receipt_signer(receipt, signer)
    evidence_id = extract_evidence_id_from_receipt(
        receipt,
        expected_case_id=case_id,
        expected_manifest_sha256=manifest_sha256
    )
    block_num = int(receipt.get("blockNumber", "0x0"), 16) if isinstance(receipt.get("blockNumber"), str) else receipt.get("blockNumber", 0)

    # 4. Ghi nhận bền vững vào SQLite (evidence_exports, custody_events, audit_events)
    db_file = db_path or os.environ.get("DB_PATH", "data/forensics.db")
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if os.path.exists(db_file):
        conn = init_db(db_file)
        with conn:
            # Cập nhật onchain_evidence_id trong evidence_exports
            conn.execute(
                "UPDATE evidence_exports SET onchain_evidence_id = ? WHERE case_id = ?",
                (evidence_id, case_id)
            )

            # Ghi nhận event vào custody_events
            event_id = f"custody-{case_id}-{evidence_id}-0"
            conn.execute(
                """INSERT OR REPLACE INTO custody_events(
                    event_id, evidence_id, case_id, action, actor_address,
                    artifact_sha256, note_hash, chain_id, contract_address,
                    tx_hash, block_number, recorded_at, verified
                ) VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (
                    event_id, evidence_id, case_id, actor,
                    manifest_sha256, dirty_note, chain_id, contract_address.lower(),
                    tx_hash.lower(), block_num, now_utc
                )
            )

            # Ghi audit_event ghi nhận cờ allow_dirty và dirty_note bền vững
            conn.execute(
                "INSERT INTO audit_events(ts, action, object_ref, metadata) VALUES(?, 'ANCHOR_EVIDENCE', ?, ?)",
                (now_utc, f"evidence:{evidence_id}", json.dumps({
                    "case_id": case_id, "tx_hash": tx_hash, "chain_id": chain_id,
                    "contract": contract_address, "allow_dirty": allow_dirty, "note": dirty_note
                }))
            )
        conn.close()

    return {
        "evidence_id": evidence_id,
        "tx_hash": tx_hash,
        "block_number": block_num,
        "contract_address": contract_address,
        "chain_id": chain_id,
        "manifest_sha256": manifest_sha256,
        "dirty_note": dirty_note
    }

def record_custody_action(
    evidence_id: int,
    action: int,
    artifact_sha256: str,
    note: str,
    contract_address: str,
    db_path: str = None,
    account: str = None,
    password_file: str = None,
    from_addr: str = None,
    rpc_url: str = None
) -> dict:
    """Ghi nhận hành trình (CustodyRecord) on-chain."""
    if not re.match(r"^0x[0-9a-fA-F]{40}$", contract_address):
        raise ValueError(f"Địa chỉ contract không hợp lệ: {contract_address}")

    url = rpc_url or os.environ.get("ANCHOR_RPC_URL", "http://127.0.0.1:8545")
    signer, chain_id = prepare_write(contract_address, url, account, password_file, from_addr)

    art_b32 = "0x" + artifact_sha256 if not artifact_sha256.startswith("0x") else artifact_sha256
    clean_note = note.strip()
    if not clean_note:
        raise ValueError("note không được để trống!")
    note_b32 = string_to_bytes32_hex(clean_note) if len(clean_note.encode('utf-8')) <= 32 else "0x" + compute_file_sha256(clean_note) if os.path.exists(clean_note) else string_to_bytes32_hex(clean_note[:32])

    cast_args = [
        contract_address,
        "recordCustody(uint256,uint8,bytes32,bytes32)",
        str(evidence_id),
        str(action),
        art_b32,
        note_b32,
        "--rpc-url", url,
        "--chain", str(chain_id),
        "--json"
    ]
    if account:
        cast_args.extend(["--account", account])
        if password_file:
            cast_args.extend(["--password-file", password_file])
    else:
        cast_args.extend(["--from", signer, "--unlocked"])

    send_out = run_cast_send(cast_args)
    try:
        tx_data = json.loads(send_out)
        tx_hash = tx_data.get("transactionHash") or tx_data.get("hash")
    except Exception:
        m = re.search(r"0x[0-9a-fA-F]{64}", send_out)
        tx_hash = m.group(0) if m else None

    if not isinstance(tx_hash, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash):
        raise RuntimeError("CAST_RESPONSE_INVALID: không nhận được transaction hash")

    receipt = get_transaction_receipt(tx_hash, url)
    actor = receipt_signer(receipt, signer)
    if receipt.get("status") not in (1, "0x1", "1"):
        raise RuntimeError("Giao dịch recordCustody thất bại trên chuỗi!")

    block_num = int(receipt.get("blockNumber", "0x0"), 16) if isinstance(receipt.get("blockNumber"), str) else receipt.get("blockNumber", 0)

    db_file = db_path or os.environ.get("DB_PATH", "data/forensics.db")
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if os.path.exists(db_file):
        conn = init_db(db_file)
        with conn:
            event_id = f"custody-step-{evidence_id}-{action}-{int(datetime.now().timestamp())}"
            conn.execute(
                """INSERT OR REPLACE INTO custody_events(
                    event_id, evidence_id, case_id, action, actor_address,
                    artifact_sha256, note_hash, chain_id, contract_address,
                    tx_hash, block_number, recorded_at, verified
                ) VALUES (?, ?, 'CUSTODY_UPDATE', ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (
                    event_id, evidence_id, action, actor,
                    art_b32, note_b32, chain_id, contract_address.lower(),
                    tx_hash.lower(), block_num, now_utc
                )
            )
            conn.execute(
                "INSERT INTO audit_events(ts, action, object_ref, metadata) VALUES(?, 'RECORD_CUSTODY', ?, ?)",
                (now_utc, f"evidence:{evidence_id}", json.dumps({
                    "evidence_id": evidence_id, "action": action, "tx_hash": tx_hash,
                    "chain_id": chain_id, "contract": contract_address
                }))
            )
        conn.close()

    return {
        "evidence_id": evidence_id,
        "action": action,
        "tx_hash": tx_hash,
        "block_number": block_num
    }

def verify_onchain_evidence(
    manifest_path_or_dir: str,
    contract_address: str,
    evidence_id: int = None,
    db_path: str = None,
    rpc_url: str = None
) -> tuple[bool, str]:
    """Xác minh tầng 3 (verify-onchain):
    Băm lại manifest.json trên đĩa, gọi verifyEvidence trên hợp đồng và đối chiếu.
    Báo MISMATCH nếu giá trị băm không khớp hoặc id không tồn tại.
    """
    manifest_file = os.path.join(manifest_path_or_dir, "manifest.json") if os.path.isdir(manifest_path_or_dir) else manifest_path_or_dir
    if not os.path.exists(manifest_file):
        return False, f"MISMATCH: Tệp manifest không tồn tại: {manifest_file}"

    current_manifest_sha256 = compute_file_sha256(manifest_file)
    with open(manifest_file, "r", encoding="utf-8") as f:
        m_data = json.load(f)
    case_id = m_data.get("case_id")

    eid = evidence_id
    db_file = db_path or os.environ.get("DB_PATH", "data/forensics.db")
    if eid is None and os.path.exists(db_file):
        conn = sqlite3.connect(db_file)
        row = conn.execute("SELECT onchain_evidence_id FROM evidence_exports WHERE case_id=?", (case_id,)).fetchone()
        conn.close()
        if row and row[0]:
            eid = row[0]

    if eid is None:
        return False, f"MISMATCH: Không xác định được evidence_id on-chain cho vụ việc '{case_id}'"

    url = rpc_url or os.environ.get("ANCHOR_RPC_URL", "http://127.0.0.1:8545")
    exp_hash_b32 = "0x" + current_manifest_sha256

    call_args = [
        contract_address,
        "verifyEvidence(uint256,bytes32)(bool,address,uint256)",
        str(eid),
        exp_hash_b32,
        "--rpc-url", url
    ]
    try:
        out = run_cast_call(call_args)
    except Exception as e:
        return False, f"MISMATCH: Lỗi khi truy vấn verifyEvidence trên hợp đồng: {e}"

    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if lines and lines[0].lower() in ("true", "1"):
        submitter = lines[1] if len(lines) > 1 else "unknown"
        registered_at = lines[2] if len(lines) > 2 else "unknown"
        return True, f"OK: Khớp 100% với bản ghi on-chain (evidence_id={eid}, submitter={submitter}, registeredAt={registered_at})"
    else:
        return False, f"MISMATCH: Dữ liệu trên đĩa không khớp với bản ghi bất biến on-chain (evidence_id={eid}, hash={current_manifest_sha256})"
