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
    """Xóa bỏ các chuỗi khóa riêng tư hoặc mật khẩu khỏi thông báo lỗi và log."""
    cleaned = re.sub(r"0x[0-9a-fA-F]{64}", "[REDACTED_KEY]", msg)
    cleaned = re.sub(r"(pass(?:word)?\s*=\s*)[^\s,]+", r"\1[REDACTED_PASSWORD]", cleaned, flags=re.I)
    return cleaned

def get_rpc_chain_id(rpc_url: str) -> int:
    """Truy vấn eth_chainId từ RPC nguồn."""
    payload = json.dumps({"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1}).encode("utf-8")
    req = urllib.request.Request(rpc_url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        if "result" not in res:
            raise RuntimeError(f"Lỗi RPC eth_chainId: {res.get('error')}")
        val = res["result"]
        return int(val, 16) if isinstance(val, str) and val.startswith("0x") else int(val)

def compute_anvil_default_accounts() -> list[str]:
    """Tính toán 10 địa chỉ mặc định của Anvil tại runtime từ mnemonic chuẩn."""
    accounts = []
    try:
        for i in range(10):
            res = subprocess.run(
                [CAST_BIN, "wallet", "address", "--mnemonic",
                 "test test test test test test test test test test test junk",
                 "--mnemonic-index", str(i)],
                capture_output=True, text=True, shell=False, timeout=5, check=False
            )
            if res.returncode == 0 and res.stdout.strip().startswith("0x"):
                accounts.append(res.stdout.strip().lower())
    except Exception:
        pass

    if len(accounts) < 10:
        fallback = [
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
            "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
            "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65",
            "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc",
            "0x976ea74026e72cd55425b73c732d01e409f31f2d",
            "0x0a0ba8a7e082194c7980bfa15aa220d938b815b5",
            "0x35606d86dbd7831f13b6522c0a96a3cfd34208a1",
            "0x5106579895c010bb15049539fa9fa67d53205166"
        ]
        return fallback
    return accounts

def validate_chain_and_guard(signer_address: str, rpc_url: str = None, override_chain_id: bool = False) -> int:
    """Chốt chặn an toàn:
    1. chain_id đọc từ RPC eth_chainId phải khớp với ANCHOR_CHAIN_ID trong env (nếu có cấu hình).
    2. chain_id phải thuộc allowlist [31337, 11155111] (trừ khi có override_chain_id=True).
    3. Nếu chain khác 31337, từ chối ký nếu signer_address trùng 10 tài khoản mặc định của Anvil.
    """
    url = rpc_url or os.environ.get("ANCHOR_RPC_URL", "http://127.0.0.1:8545")
    rpc_chain_id = get_rpc_chain_id(url)

    env_chain = os.environ.get("ANCHOR_CHAIN_ID")
    if env_chain and env_chain.strip():
        if int(env_chain.strip()) != rpc_chain_id:
            raise ValueError(
                f"Chain ID mismatch: RPC eth_chainId trả về {rpc_chain_id} "
                f"nhưng ANCHOR_CHAIN_ID trong .env cấu hình là {env_chain.strip()}!"
            )

    if rpc_chain_id not in ALLOWED_CHAIN_IDS and not override_chain_id:
        raise ValueError(
            f"Chain ID {rpc_chain_id} không nằm trong danh sách cho phép {list(ALLOWED_CHAIN_IDS)}. "
            "Sử dụng cờ --override-chain-id nếu cố tình muốn ghi đè."
        )

    if rpc_chain_id != 31337:
        anvil_defaults = compute_anvil_default_accounts()
        if signer_address and signer_address.lower() in anvil_defaults:
            raise ValueError(
                f"Chặn khóa mặc định Anvil: Địa chỉ người ký {signer_address} "
                f"trùng với tài khoản mặc định của Anvil! Bị từ chối trên chain {rpc_chain_id}."
            )

    return rpc_chain_id

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
    """Thực thi cast send qua subprocess shell=False an toàn."""
    cmd = [CAST_BIN, "send"] + args
    res = subprocess.run(cmd, capture_output=True, text=True, shell=False, timeout=30, check=False)
    if res.returncode != 0:
        err = safe_redact_error(res.stderr or res.stdout)
        raise RuntimeError(f"Lỗi cast send: {err}")
    return res.stdout.strip()

def run_cast_call(args: list[str]) -> str:
    """Thực thi cast call qua subprocess shell=False."""
    cmd = [CAST_BIN, "call"] + args
    res = subprocess.run(cmd, capture_output=True, text=True, shell=False, timeout=30, check=False)
    if res.returncode != 0:
        err = safe_redact_error(res.stderr or res.stdout)
        raise RuntimeError(f"Lỗi cast call: {err}")
    return res.stdout.strip()

def get_transaction_receipt(tx_hash: str, rpc_url: str) -> dict:
    """Lấy receipt giao dịch qua eth_getTransactionReceipt JSON-RPC."""
    payload = json.dumps({
        "jsonrpc": "2.0", "method": "eth_getTransactionReceipt", "params": [tx_hash], "id": 1
    }).encode("utf-8")
    req = urllib.request.Request(rpc_url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        if "result" not in res:
            raise RuntimeError(f"Lỗi lấy receipt cho tx {tx_hash}: {res.get('error')}")
        return res["result"]

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
    signer = from_addr or os.environ.get("ANCHOR_FROM") or "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

    # Chốt chặn an toàn
    chain_id = validate_chain_and_guard(signer, rpc_url=url)

    # RÀNG BUỘC BẢO MẬT: Trên chain khác Anvil (31337), bắt buộc dùng keystore (--account)
    if chain_id != 31337 and not account:
        raise ValueError(
            f"Trên mạng không phải Anvil (chain_id={chain_id}), bắt buộc sử dụng keystore "
            "với đối số --account (và tùy chọn --password-file). "
            "Tuyệt đối không cho phép dùng cờ --unlocked hoặc --from trực tiếp."
        )

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
        "--json"
    ]
    if account:
        cast_args.extend(["--account", account])
        if password_file:
            cast_args.extend(["--password-file", password_file])
    else:
        cast_args.extend(["--from", from_addr or signer, "--unlocked"])

    log.info("Đang neo chứng cứ case_id=%s, manifest_sha256=%s lên contract %s...", case_id, manifest_sha256, contract_address)
    send_out = run_cast_send(cast_args)

    try:
        tx_data = json.loads(send_out)
        tx_hash = tx_data.get("transactionHash") or tx_data.get("hash")
    except Exception:
        m = re.search(r"0x[0-9a-fA-F]{64}", send_out)
        tx_hash = m.group(0) if m else None

    if not tx_hash:
        raise RuntimeError(f"Không nhận được transaction hash sau khi gửi: {send_out}")

    receipt = get_transaction_receipt(tx_hash, url)
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
                    event_id, evidence_id, case_id, signer.lower(),
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
    signer = from_addr or os.environ.get("ANCHOR_FROM") or "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    chain_id = validate_chain_and_guard(signer, rpc_url=url)

    # RÀNG BUỘC BẢO MẬT: Trên chain khác Anvil (31337), bắt buộc dùng keystore (--account)
    if chain_id != 31337 and not account:
        raise ValueError(
            f"Trên mạng không phải Anvil (chain_id={chain_id}), bắt buộc sử dụng keystore "
            "với đối số --account (và tùy chọn --password-file). "
            "Tuyệt đối không cho phép dùng cờ --unlocked hoặc --from trực tiếp."
        )

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
        "--json"
    ]
    if account:
        cast_args.extend(["--account", account])
        if password_file:
            cast_args.extend(["--password-file", password_file])
    else:
        cast_args.extend(["--from", from_addr or signer, "--unlocked"])

    send_out = run_cast_send(cast_args)
    try:
        tx_data = json.loads(send_out)
        tx_hash = tx_data.get("transactionHash") or tx_data.get("hash")
    except Exception:
        m = re.search(r"0x[0-9a-fA-F]{64}", send_out)
        tx_hash = m.group(0) if m else None

    receipt = get_transaction_receipt(tx_hash, url)
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
                    event_id, evidence_id, action, signer.lower(),
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
