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
import hashlib
import logging
import sqlite3
import subprocess
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
import uuid

from forensics.integrity import verify_package
from forensics.provenance import inspect_commit_provenance

from forensics.evidence import (
    compute_file_sha256,
    is_working_tree_dirty,
    validate_case_id,
)
from forensics.schemas import init_db
from forensics.evidence_identity import (
    case_id_digest,
    case_id_hash_bytes32,
    note_hash_bytes32,
    canonical_storage_uri,
    identity_for_verify,
    sanitize_log_text,
    sha256_utf8,
    string_to_bytes32_hex,
)
from forensics import onchain_store as ops

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
        err_msg = res.stderr.strip() if res.stderr else "công cụ không hoàn tất yêu cầu"
        raise RuntimeError(f"CAST_EXIT_{int(res.returncode)}: {err_msg}")
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
        if configured_chain != rpc_chain_id and not (configured_chain == 31337 and rpc_chain_id == 11155111):
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

def _require(condition, code):
    if not condition:
        raise ValueError(code)




def _bytes(value, size=None):
    _require(isinstance(value, str) and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value), "ABI_INVALID")
    raw = bytes.fromhex(value[2:])
    _require(size is None or len(raw) == size, "ABI_INVALID")
    _require(len(raw) <= 4096, "ABI_INVALID")
    return raw


def _word(value):
    _require(type(value) is int and 0 <= value < 2**256, "UINT_INVALID")
    return value.to_bytes(32, 'big').hex()


def _uint(value):
    if type(value) is int:
        _require(0 <= value < 2**256, "UINT_INVALID")
        return value
    _require(isinstance(value, str) and re.fullmatch(r'0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)', value)
             and len(value) <= 66, "UINT_INVALID")
    return int(value, 16)


def _address_word(raw):
    _require(len(raw) == 32 and raw[:12] == b'\0'*12, "ABI_INVALID")
    return '0x' + raw[12:].hex()


def _abi_string(raw, head_size, offset_word):
    _require(len(raw) >= head_size+32 and int.from_bytes(offset_word, 'big') == head_size, "ABI_INVALID")
    length = int.from_bytes(raw[head_size:head_size+32], 'big')
    _require(0 < length <= 256, "ABI_INVALID")
    end = head_size + 32 + length
    padded = head_size + 32 + ((length+31)//32)*32
    _require(len(raw) == padded and not any(raw[end:padded]), "ABI_INVALID")
    try:
        return raw[head_size+32:end].decode('utf-8', errors='strict')
    except UnicodeError:
        raise ValueError('ABI_INVALID') from None


def _receipt_success(receipt):
    if not isinstance(receipt, dict) or type(receipt.get('status')) is bool or receipt.get('status') not in (1, '0x1'):
        raise RuntimeError('Giao dịch on-chain thất bại: RECEIPT_STATUS')


def validate_write_receipt(receipt, tx_hash, contract, signer):
    actor = receipt_signer(receipt, signer)
    _receipt_success(receipt)
    _require(_bytes(receipt.get('transactionHash'),32) == _bytes(tx_hash,32), 'RECEIPT_TX_MISMATCH')
    _require(normalize_address(receipt.get('to')) == normalize_address(contract), 'RECEIPT_CONTRACT_MISMATCH')
    _bytes(receipt.get('blockHash'),32)
    _uint(receipt.get('blockNumber')); _uint(receipt.get('transactionIndex'))
    _require(isinstance(receipt.get('logs'),list), 'RECEIPT_LOGS_INVALID')
    return actor


def _event_logs(receipt, topic, contract=None):
    _receipt_success(receipt)
    _require(isinstance(receipt.get('logs'),list), 'RECEIPT_LOGS_INVALID')
    found=[]
    for log_entry in receipt['logs']:
        _require(isinstance(log_entry,dict), 'EVENT_INVALID')
        topics=log_entry.get('topics')
        _require(isinstance(topics,list), 'EVENT_INVALID')
        if not topics or not isinstance(topics[0],str) or topics[0].lower()!=topic:
            continue
        label='EvidenceRegistered' if topic==TOPIC_EVIDENCE_REGISTERED else 'CustodyRecorded'
        _require(len(topics)==4, f'Event {label} không hợp lệ hoặc thiếu indexed topics')
        for t in topics: _bytes(t,32)
        emitter=normalize_address(log_entry.get('address'))
        if contract is not None:
            _require(emitter==normalize_address(contract), 'EVENT_EMITTER_MISMATCH')
        _require(log_entry.get('removed',False) is False, 'EVENT_REMOVED')
        if 'transactionHash' in receipt:
            for field in ('transactionHash','blockHash'):
                _require(_bytes(log_entry.get(field),32)==_bytes(receipt[field],32), 'EVENT_IDENTITY_MISMATCH')
            for field in ('transactionIndex','blockNumber'):
                _require(_uint(log_entry.get(field))==_uint(receipt[field]), 'EVENT_IDENTITY_MISMATCH')
            _uint(log_entry.get('logIndex'))
        found.append(log_entry)
    label='EvidenceRegistered' if topic==TOPIC_EVIDENCE_REGISTERED else 'CustodyRecorded'
    _require(len(found)==1, f'Không tìm thấy event {label} hợp lệ: EVENT_MISSING_OR_AMBIGUOUS')
    return found[0]


def extract_evidence_id_from_receipt(receipt, expected_case_id=None, expected_manifest_sha256=None,
                                     expected_contract=None, expected_submitter=None, expected_uri=None,
                                     legacy_case_encoding: bool = False):
    event = _event_logs(receipt, TOPIC_EVIDENCE_REGISTERED, expected_contract)
    topics = event['topics']
    eid = int(topics[1], 16)
    _require(eid > 0, 'EVENT_ID_INVALID')
    if expected_case_id is not None:
        if legacy_case_encoding:
            leg_topic = string_to_bytes32_hex(expected_case_id).lower()
            _require(topics[2].lower() == leg_topic, 'Event caseId mismatch')
        else:
            can_topic = case_id_hash_bytes32(expected_case_id).lower()
            _require(topics[2].lower() == can_topic, 'Event caseId mismatch')
    if expected_manifest_sha256 is not None:
        expected = '0x' + expected_manifest_sha256.removeprefix('0x')
        _require(_bytes(topics[3], 32) == _bytes(expected, 32), 'Event manifestSha256 mismatch')
    data = _bytes(event.get('data'))
    _require(len(data) >= 96, 'ABI_INVALID')
    submitter = _address_word(data[:32]); uri = _abi_string(data, 64, data[32:64])
    if expected_submitter is not None:
        _require(submitter == normalize_address(expected_submitter), 'EVENT_SUBMITTER_MISMATCH')
    if expected_uri is not None:
        _require(uri == expected_uri, 'EVENT_URI_MISMATCH')
    return eid


def verify_custody_receipt(receipt, contract, signer, evidence_id, action, artifact, note, raw_note=None, legacy_case_encoding: bool = False):
    event = _event_logs(receipt, TOPIC_CUSTODY_RECORDED, contract)
    topics = event['topics']; data = _bytes(event.get('data'), 64)
    _require(int(topics[1], 16) == evidence_id and int(topics[2], 16) == action and action in range(4), 'CUSTODY_EVENT_MISMATCH')
    _require(_address_word(_bytes(topics[3], 32)) == signer, 'CUSTODY_ACTOR_MISMATCH')
    match_art = (data[:32] == _bytes(artifact, 32))
    if legacy_case_encoding:
        match_note = (data[32:] == _bytes(note, 32)) or (
            raw_note is not None and len(raw_note.encode('utf-8')) <= 32 and data[32:] == _bytes(string_to_bytes32_hex(raw_note), 32)
        )
    else:
        match_note = (data[32:] == _bytes(note, 32))
    _require(match_art and match_note, 'CUSTODY_DATA_MISMATCH')

def run_cast_send(args: list[str]) -> str:
    return _run_cast(["send"] + args)


def run_cast_call(args: list[str]) -> str:
    return _run_cast(["call"] + args)


def get_transaction_receipt(tx_hash: str, rpc_url: str) -> dict:
    return rpc_read(rpc_url, "eth_getTransactionReceipt", [tx_hash])

REASONS = frozenset({'controlled-test', 'incomplete-collection-review', 'reproducibility-review'})


def package_preflight(path, allow_integrity_failed=False):
    result=verify_package(path)
    if allow_integrity_failed and result.status=='INVALID':
        diagnostic=verify_package(path, declaration_diagnostic=True)
        _require(diagnostic.manifest_sha256==result.manifest_sha256, 'PACKAGE_UNSTABLE')
        if diagnostic.details.get('declaration_failed') and diagnostic.context:
            result=diagnostic
    eligible=(result.status=='VALID' and result.coverage=='FULL') or (
        allow_integrity_failed and result.status=='INVALID' and result.details.get('declaration_failed') and result.context)
    if not eligible:
        if result.status=='ERROR':raise RuntimeError('PACKAGE_'+result.reason_code.value)
        raise ValueError('PACKAGE_'+result.reason_code.value if result.status!='VALID' else 'PACKAGE_LIMITED')
    return result


def check_anchor_policy(result, provenance, chain_id, flags, reason):
    requested=[name for name,value in flags.items() if value]
    _require(not requested or reason in REASONS, 'REASON_REQUIRED')
    _require(reason is None or reason in REASONS, 'REASON_INVALID')
    _require(chain_id==31337 or not result.context['synthetic'], 'SYNTHETIC_PUBLIC_FORBIDDEN')
    _require(chain_id==31337 or not flags['allow_integrity_failed'], 'INTEGRITY_OVERRIDE_LOCAL_ONLY')
    status=provenance['status']
    if status=='INDETERMINATE':raise RuntimeError('GIT_UNKNOWN')
    _require(status in ('OK','EXISTING_NON_ANCESTOR'), 'PROVENANCE_'+status)
    applied=[]
    conditions={
        'allow_commit_mismatch':status=='EXISTING_NON_ANCESTOR',
        'allow_dirty':provenance['git_state']=='DIRTY' or result.context['working_tree_dirty'],
        'allow_gaps':result.details['gaps_count']>0,
        'allow_unfinalized':not result.details['is_finalized'],
        'allow_integrity_failed':bool(result.details.get('declaration_failed'))}
    for name,condition in conditions.items():
        if condition:
            _require(flags[name], 'POLICY_'+name.upper())
            applied.append(name)
    return {'requested_flags':requested, 'applied_exceptions':applied, 'reason':reason}


def pre_send_audit(db_path, metadata):
    _require(Path(db_path).is_file(), 'AUDIT_DB_REQUIRED')
    attempt=uuid.uuid4().hex
    try:
        conn=sqlite3.connect(Path(db_path).absolute().as_uri()+'?mode=rw', uri=True, timeout=2)
        try:
            conn.execute("INSERT INTO audit_events(ts,action,object_ref,metadata) VALUES(?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), 'ANCHOR_PREFLIGHT', 'attempt:'+attempt,
                 json.dumps(metadata, sort_keys=True)))
            conn.commit()
        finally:conn.close()
    except sqlite3.Error:
        raise RuntimeError('AUDIT_COMMIT_FAILED') from None
    return attempt


def anchor_evidence(manifest_path_or_dir, contract_address, db_path=None, account=None,
                    password_file=None, from_addr=None, allow_dirty=False, rpc_url=None,
                    allow_unfinalized=False, allow_gaps=False, allow_integrity_failed=False,
                    allow_commit_mismatch=False, reason=None):
    contract_address=normalize_address(contract_address)
    result=package_preflight(manifest_path_or_dir, allow_integrity_failed)
    provenance=inspect_commit_provenance(result.context['export_commit'])
    url=rpc_url or os.environ.get('ANCHOR_RPC_URL','http://127.0.0.1:8545')
    chain_id=get_rpc_chain_id(url)
    flags=dict(allow_dirty=allow_dirty,allow_unfinalized=allow_unfinalized,allow_gaps=allow_gaps,
               allow_integrity_failed=allow_integrity_failed,allow_commit_mismatch=allow_commit_mismatch)
    # Preserve guard precedence for signer/loopback/chain failures before any audit write.
    signer, guarded_chain=prepare_write(contract_address,url,account,password_file,from_addr)
    _require(chain_id==guarded_chain,'CHAIN_UNSTABLE')
    policy=check_anchor_policy(result,provenance,chain_id,flags,reason)
    manifest_sha256=result.manifest_sha256;case_id=result.context['case_id']
    case_digest=case_id_digest(case_id)
    case_id_b32='0x'+case_digest
    manifest_hash_b32='0x'+manifest_sha256
    storage_uri=canonical_storage_uri(case_digest,manifest_sha256)
    dirty_note='ALLOW_DIRTY_WARNING' if 'allow_dirty' in policy['applied_exceptions'] else 'CLEAN_TREE'
    db_file=db_path or os.environ.get('DB_PATH','data/forensics.db')
    ops.pre_send_db_check(db_file, migrate=False)
    attempt=pre_send_audit(db_file,dict(policy,manifest_sha256=manifest_sha256,
        source_chain_id=result.context['chain_id'],anchor_chain_id=chain_id,contract=contract_address,
        signer=signer,export_commit=result.context['export_commit'],trusted_head=provenance['head'],
        provenance=provenance['status'],integrity=result.status,case_digest=case_digest))
    intent = ops.register_intent(chain_id, contract_address, manifest_sha256, case_digest, storage_uri, signer)
    claim = ops.claim_send(db_file, intent)
    _require(claim.can_send, 'IDEMPOTENCY_CLAIM_DENIED')
    operation_id = claim.operation_id
    stable = package_preflight(manifest_path_or_dir, allow_integrity_failed)
    _require(stable == result, 'PACKAGE_UNSTABLE')
    _require(inspect_commit_provenance(result.context['export_commit']) == provenance, 'GIT_UNSTABLE')
    _require(get_rpc_chain_id(url) == chain_id, 'CHAIN_UNSTABLE')
    cast_args = [contract_address, 'registerEvidence(bytes32,bytes32,string)', case_id_b32, manifest_hash_b32,
                 storage_uri, '--rpc-url', url, '--chain', str(chain_id), '--json']
    if account:
        cast_args += ['--account', account]
        if password_file: cast_args += ['--password-file', password_file]
    else: cast_args += ['--from', signer, '--unlocked']
    log.info('ANCHOR_SEND manifest_sha256=%s chain_id=%s', manifest_sha256, chain_id)
    try:
        send_out = run_cast_send(cast_args)  # Exactly one attempt; ambiguous outcomes never retry.
    except Exception:
        ops.mark_unknown(db_file, operation_id, 'SEND_EXCEPTION')
        raise
    try:
        tx_data = json.loads(send_out); tx_hash = tx_data.get('transactionHash') or tx_data.get('hash')
        _bytes(tx_hash, 32)
    except (ValueError, TypeError, AttributeError, json.JSONDecodeError):
        ops.mark_unknown(db_file, operation_id, 'SEND_OUTCOME_UNKNOWN')
        raise RuntimeError('CAST_RESPONSE_INVALID: SEND_OUTCOME_UNKNOWN') from None
    try:
        ops.record_broadcast(db_file, operation_id, tx_hash)
    except Exception:
        ops.write_sidecar(db_file, {'operation_id': operation_id, 'tx_hash': tx_hash, 'state': 'UNKNOWN', 'code': 'POST_SEND_DB_FAILED'})
        raise RuntimeError('POST_SEND_DB_FAILED') from None
    receipt = get_transaction_receipt(tx_hash, url)
    actor = validate_write_receipt(receipt, tx_hash, contract_address, signer)
    evidence_id = extract_evidence_id_from_receipt(receipt, case_id, manifest_sha256, contract_address, signer, storage_uri)
    event = _event_logs(receipt, TOPIC_EVIDENCE_REGISTERED, contract_address)
    _require(get_rpc_chain_id(url) == chain_id, 'CHAIN_UNSTABLE')
    state = read_registered_state(url, contract_address, evidence_id, receipt['blockNumber'])
    check_registered_state(state, evidence_id, case_id_b32, manifest_hash_b32, signer, storage_uri, case_id=case_id)
    check_receipt_block(url, receipt)
    block_num = _uint(receipt['blockNumber'])
    try:
        ops.persist_verified_event(
            db_file, operation_id, chain_id=chain_id, contract=contract_address, evidence_id=evidence_id,
            action=0, actor=actor, artifact_sha256=manifest_sha256, note_hash=sha256_utf8(dirty_note),
            tx_hash=tx_hash, block_number=block_num, log_index=_uint(event.get('logIndex')),
            event_type='EvidenceRegistered', manifest_sha256=manifest_sha256, case_digest=case_digest,
            receipt=receipt)
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        persist_conn = ops.open_existing_rw(db_file, migrate_before_send=False)
        try:
            persist_conn.execute('BEGIN IMMEDIATE')
            persist_conn.execute(
                "INSERT INTO audit_events(ts, action, object_ref, metadata) VALUES(?, 'ANCHOR_EVIDENCE', ?, ?)",
                (now_utc, f"evidence:{evidence_id}", json.dumps({
                    "tx_hash": tx_hash, "chain_id": chain_id,
                    "contract": contract_address, "allow_dirty": allow_dirty, "policy_note": dirty_note,
                    "operation_id": operation_id
                }))
            )
            persist_conn.commit()
        finally:
            persist_conn.close()
    except Exception:
        ops.write_sidecar(db_file, {'operation_id': operation_id, 'tx_hash': tx_hash, 'state': 'BROADCAST', 'code': 'POST_SEND_DB_FAILED'})
        raise RuntimeError('POST_SEND_DB_FAILED') from None

    return {
        "evidence_id": evidence_id,
        "tx_hash": tx_hash,
        "block_number": block_num,
        "contract_address": contract_address,
        "chain_id": chain_id,
        "manifest_sha256": manifest_sha256,
        "dirty_note": dirty_note, "attempt_id": attempt, "operation_id": operation_id,
        "status": "ANCHORED_WITH_EXCEPTION" if policy["applied_exceptions"] else "ANCHORED"
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

    if not isinstance(note, str) or not note.strip():
        raise ValueError("note không được để trống!")
    note_b32 = note_hash_bytes32(note)
    art_b32 = "0x" + artifact_sha256.removeprefix("0x")

    url = rpc_url or os.environ.get("ANCHOR_RPC_URL", "http://127.0.0.1:8545")
    signer, chain_id = prepare_write(contract_address, url, account, password_file, from_addr)

    db_file = db_path or os.environ.get("DB_PATH", "data/forensics.db")
    ops.pre_send_db_check(db_file, migrate=False)
    intent = ops.custody_intent(chain_id, contract_address, evidence_id, action, art_b32, note_b32, signer)
    claim = ops.claim_send(db_file, intent)
    _require(claim.can_send, 'IDEMPOTENCY_CLAIM_DENIED')
    operation_id = claim.operation_id

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

    log.info('CUSTODY_SEND evidence_id=%s action=%s chain_id=%s', evidence_id, action, chain_id)
    try:
        send_out = run_cast_send(cast_args)
    except Exception:
        ops.mark_unknown(db_file, operation_id, 'SEND_EXCEPTION')
        raise

    try:
        tx_data = json.loads(send_out)
        tx_hash = tx_data.get("transactionHash") or tx_data.get("hash")
        _bytes(tx_hash, 32)
    except (ValueError, TypeError, AttributeError, json.JSONDecodeError):
        ops.mark_unknown(db_file, operation_id, 'SEND_OUTCOME_UNKNOWN')
        raise RuntimeError("CAST_RESPONSE_INVALID: không nhận được transaction hash") from None

    try:
        ops.record_broadcast(db_file, operation_id, tx_hash)
    except Exception:
        ops.write_sidecar(db_file, {'operation_id': operation_id, 'tx_hash': tx_hash, 'state': 'UNKNOWN', 'code': 'POST_SEND_DB_FAILED'})
        raise RuntimeError('POST_SEND_DB_FAILED') from None

    receipt = get_transaction_receipt(tx_hash, url)
    actor = validate_write_receipt(receipt, tx_hash, contract_address, signer)
    verify_custody_receipt(receipt, contract_address, signer, evidence_id, action, art_b32, note_b32, raw_note=None, legacy_case_encoding=False)
    _require(get_rpc_chain_id(url) == chain_id, 'CHAIN_UNSTABLE')
    check_receipt_block(url, receipt)
    block_num = _uint(receipt['blockNumber'])
    event = ops.verify_receipt_and_event(
        receipt,
        'CustodyRecorded',
        expected_contract=contract_address,
        expected_tx_hash=tx_hash,
        expected_actor=actor,
        expected_evidence_id=evidence_id,
        expected_action=action,
        expected_artifact_sha256=art_b32,
        expected_note_hash=note_b32,
        legacy_case_encoding=False,
    )
    log_index = _uint(event.get('logIndex'))

    try:
        ops.persist_verified_event(
            db_file,
            operation_id=operation_id,
            chain_id=chain_id,
            contract=contract_address,
            evidence_id=evidence_id,
            action=action,
            actor=actor,
            artifact_sha256=art_b32.removeprefix("0x"),
            note_hash=note_b32.removeprefix("0x"),
            tx_hash=tx_hash,
            block_number=block_num,
            log_index=log_index,
            event_type='CustodyRecorded',
            receipt=receipt,
            legacy_case_encoding=False,
        )
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        persist_conn = ops.open_existing_rw(db_file, migrate_before_send=False)
        try:
            persist_conn.execute("BEGIN IMMEDIATE")
            persist_conn.execute(
                "INSERT INTO audit_events(ts, action, object_ref, metadata) VALUES(?, 'RECORD_CUSTODY', ?, ?)",
                (now_utc, f"evidence:{evidence_id}", json.dumps({
                    "evidence_id": evidence_id, "action": action, "tx_hash": tx_hash,
                    "chain_id": chain_id, "contract": contract_address,
                    "operation_id": operation_id
                }))
            )
            persist_conn.commit()
        finally:
            persist_conn.close()
    except Exception:
        ops.write_sidecar(db_file, {'operation_id': operation_id, 'tx_hash': tx_hash, 'state': 'BROADCAST', 'code': 'POST_SEND_DB_FAILED'})
        raise RuntimeError('POST_SEND_DB_FAILED') from None

    return {
        "evidence_id": evidence_id,
        "action": action,
        "tx_hash": tx_hash,
        "block_number": block_num,
        "operation_id": operation_id
    }

def check_receipt_block(url, receipt):
    block=rpc_read(url,'eth_getBlockByNumber',[receipt['blockNumber'],False])
    if not isinstance(block,dict) or block.get('hash','').lower()!=receipt['blockHash'].lower():
        raise RuntimeError('CHAIN_UNSTABLE')


def read_registered_state(url, contract, evidence_id, block='latest'):
    raw=_bytes(rpc_read(url,'eth_call',[{'to':contract,'data':'0xc956f143'+_word(evidence_id)},block]))
    _require(len(raw)>=288 and raw[:32]==bytes.fromhex(_word(32)), 'ABI_INVALID')
    body=raw[32:];uri=_abi_string(body,224,body[96:128])
    _require(int.from_bytes(body[192:224],'big') in (0,1),'ABI_INVALID')
    return {'id':int.from_bytes(body[:32],'big'),'case':'0x'+body[32:64].hex(),
        'hash':'0x'+body[64:96].hex(),'uri':uri,'submitter':_address_word(body[128:160]),
        'registered_at':int.from_bytes(body[160:192],'big'),'exists':bool(int.from_bytes(body[192:224],'big'))}


def check_registered_state(state,eid,case_hash,manifest_hash,submitter,uri,case_id=None):
    _require(state['exists'] and state['id']==eid and
        state['case'].lower()==case_hash.lower() and
        state['hash'].lower()==manifest_hash.lower() and
        state['submitter'].lower()==submitter.lower() and
        state['uri']==uri,
        'REGISTRY_MISMATCH')


@dataclass
class OnchainVerification:
    status: str
    reason_code: str
    details: dict = field(default_factory=dict)

    @property
    def exit_code(self):
        return {'MATCH':0,'MISMATCH':1,'ERROR':2}[self.status]

    def __iter__(self):
        # Existing Python callers may unpack; boolean is true only on complete MATCH.
        yield self.status=='MATCH'
        yield self.status+': '+self.reason_code


def verify_onchain_evidence(manifest_path_or_dir, contract_address, evidence_id=None, db_path=None,
                            rpc_url=None, anchor_chain_id=None, legacy_case_encoding: bool = False):
    details={'chain_check':'NOT_RUN'}
    try:
        result=verify_package(manifest_path_or_dir)
        if result.status!='VALID' or result.coverage!='FULL':
            return OnchainVerification('ERROR' if result.status=='ERROR' else 'MISMATCH',
                result.reason_code.value if result.status!='VALID' else 'PACKAGE_LIMITED',details)
        provenance=inspect_commit_provenance(result.context['export_commit'])
        if provenance['status']!='OK':
            return OnchainVerification('ERROR' if provenance['status']=='INDETERMINATE' else 'MISMATCH',
                                       'PROVENANCE_'+provenance['status'],details)
        contract=normalize_address(contract_address)
        configured=os.environ.get('ANCHOR_CHAIN_ID')
        def context_chain(value):
            if isinstance(value,str) and re.fullmatch(r'[0-9]+',value):
                try:value=int(value)
                except (ValueError,OverflowError):
                    raise ValueError('ANCHOR_CONTEXT_INVALID') from None
            _require(type(value) is int and value>0,'ANCHOR_CONTEXT_INVALID')
            return value
        explicit=context_chain(anchor_chain_id) if anchor_chain_id is not None else None
        configured=context_chain(configured) if configured is not None else None
        if explicit is not None and configured is not None and explicit!=configured:
            if not (configured == 31337 and explicit == 11155111):
                raise RuntimeError('ANCHOR_CONTEXT_CONFLICT')
            expected = explicit
        else:
            expected=explicit if explicit is not None else configured
        if expected is None:raise RuntimeError('ANCHOR_CONTEXT_REQUIRED')
        url=rpc_url or os.environ.get('ANCHOR_RPC_URL','http://127.0.0.1:8545')
        chain=get_rpc_chain_id(url)
        details.update(source_chain_id=result.context['chain_id'],anchor_chain_id=chain,contract=contract)
        _require(chain==expected,'ANCHOR_CHAIN_MISMATCH')
        details['chain_check']='CHECKED'
        code=rpc_read(url,'eth_getCode',[contract,'latest'])
        _require(isinstance(code,str) and re.fullmatch(r'0x(?:[0-9a-fA-F]{2})+',code), 'CONTRACT_CODE_MISSING')
        digest=result.manifest_sha256
        mapped=_bytes(rpc_read(url,'eth_call',[{'to':contract,'data':'0x5a9535b7'+digest},'latest']),32)
        eid=int.from_bytes(mapped,'big')
        _require(eid>0,'EVIDENCE_NOT_FOUND')
        if evidence_id is not None:
            _require(type(evidence_id) is int and evidence_id>0,'EVIDENCE_ID_INVALID')
            _require(eid==evidence_id,'EVIDENCE_ID_MISMATCH')
        # DB is never authoritative for ID; this read path neither opens a wallet nor writes DB.
        state=read_registered_state(url,contract,eid)
        case_hash, uri = identity_for_verify(result.context['case_id'], digest, legacy_case_encoding=legacy_case_encoding)
        check_registered_state(state,eid,case_hash,'0x'+digest,state['submitter'],uri,case_id=result.context['case_id'])
        response=_bytes(rpc_read(url,'eth_call',[{'to':contract,'data':'0x9fcc7309'+_word(eid)+digest},'latest']),96)
        _require(int.from_bytes(response[:32],'big') in (0,1),'ABI_INVALID')
        _require(response[:32]==bytes.fromhex(_word(1)) and _address_word(response[32:64])==state['submitter']
                 and int.from_bytes(response[64:],'big')==state['registered_at'],'REGISTRY_MISMATCH')
        # Find the first block at/after registeredAt; bounded binary search avoids unbounded log scans.
        latest=rpc_read(url,'eth_getBlockByNumber',['latest',False])
        _require(isinstance(latest,dict),'RPC_BLOCK_INVALID')
        low,high=0,_uint(latest.get('number'))
        if high.bit_length()>64:raise RuntimeError('RPC_RANGE_LIMIT')
        while low<high:
            mid=(low+high)//2
            block=rpc_read(url,'eth_getBlockByNumber',[hex(mid),False])
            if not isinstance(block,dict):raise RuntimeError('RPC_BLOCK_INVALID')
            if _uint(block.get('timestamp'))<state['registered_at']:low=mid+1
            else:high=mid
        logs=rpc_read(url,'eth_getLogs',[{'address':contract,'fromBlock':hex(low),'toBlock':hex(low),
             'topics':[TOPIC_EVIDENCE_REGISTERED,'0x'+_word(eid),case_hash,'0x'+digest]}])
        if not isinstance(logs,list) or len(logs)!=1:raise RuntimeError('REGISTRATION_EVENT_UNAVAILABLE')
        tx_hash=logs[0].get('transactionHash');_bytes(tx_hash,32)
        receipt=get_transaction_receipt(tx_hash,url)
        validate_write_receipt(receipt,tx_hash,contract,state['submitter'])
        actual=extract_evidence_id_from_receipt(receipt,result.context['case_id'],digest,contract,state['submitter'],uri,legacy_case_encoding=legacy_case_encoding)
        _require(actual==eid and logs[0] in receipt['logs'],'EVENT_IDENTITY_MISMATCH')
        tx=rpc_read(url,'eth_getTransactionByHash',[tx_hash])
        if not isinstance(tx,dict):raise RuntimeError('TRANSACTION_UNAVAILABLE')
        _require(_bytes(tx.get('hash'),32)==_bytes(tx_hash,32) and normalize_address(tx.get('from'))==state['submitter']
            and normalize_address(tx.get('to'))==contract,'TRANSACTION_MISMATCH')
        if 'chainId' in tx:_require(_uint(tx['chainId'])==chain,'TRANSACTION_CHAIN_MISMATCH')
        check_receipt_block(url,receipt)
        _require(get_rpc_chain_id(url)==chain,'CHAIN_UNSTABLE')
        final=verify_package(manifest_path_or_dir)
        if final!=result:raise RuntimeError('PACKAGE_UNSTABLE')
        if inspect_commit_provenance(result.context['export_commit'])!=provenance:raise RuntimeError('GIT_UNSTABLE')
        details.update(evidence_id=eid,manifest_sha256=digest,registry_match=True,submitter=state['submitter'],tx_hash=tx_hash,legacy_case_encoding=legacy_case_encoding)
        reason_code = 'LEGACY_PUBLIC_CASE_ID' if legacy_case_encoding else 'OK'
        return OnchainVerification('MATCH',reason_code,details)
    except (RuntimeError,OSError,sqlite3.Error) as exc:
        code=str(exc)
        return OnchainVerification('ERROR',code if re.fullmatch(r'[A-Z_]+',code) else 'OPERATION_FAILED',details)
    except (ValueError,TypeError,KeyError,IndexError,OverflowError) as exc:
        code=str(exc)
        if code in ('ABI_INVALID','RPC_BLOCK_INVALID','UINT_INVALID','ANCHOR_CONTEXT_INVALID'):
            return OnchainVerification('ERROR',code,details)
        return OnchainVerification('MISMATCH',code if re.fullmatch(r'[A-Z_]+',code) else 'EVENT_OR_INPUT_MISMATCH',details)
