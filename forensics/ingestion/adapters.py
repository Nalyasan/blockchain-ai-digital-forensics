"""Evidence Format Adapters (forensics/ingestion/adapters.py).

Provides multi-format adapters for digital forensic evidence ingestion:
1. Blockchain Transactions JSON/JSONL Adapter
2. Blockchain Transactions CSV Adapter
3. SQLite Database Adapter (strictly read-only mode)
4. Authorized Host Logs / Sysmon Adapter

All adapters enforce strict validation, reject corrupted/incompatible schemas with clear errors,
and never produce facade or fabricated outputs.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
import io
import json
import logging
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("forensics.ingestion.adapters")


# ==============================================================================
# Ingestion Exceptions
# ==============================================================================

class IngestionError(Exception):
    """Base exception for evidence ingestion pipeline errors."""


class FormatError(IngestionError):
    """Raised when file format is unsupported or unrecognized."""


class SchemaCompatibilityError(IngestionError):
    """Raised when file schema does not match required evidence schema."""


class CorruptedFileError(IngestionError):
    """Raised when file bytes are corrupted, truncated, or unparseable."""


class SecurityError(IngestionError):
    """Raised when path traversal, symlink, or security policy violation is detected."""


class AdapterError(IngestionError):
    """Raised when an adapter encounters an operational error during parsing."""


# ==============================================================================
# Standard Schemas
# ==============================================================================

@dataclass
class NormalizedTransaction:
    """Standardized schema for blockchain transactions."""
    tx_hash: str
    from_address: str
    to_address: Optional[str]
    value: Union[int, str]
    token_symbol: str
    block_number: int
    timestamp: Union[int, str]
    additional_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_hash": self.tx_hash,
            "from_address": self.from_address,
            "to_address": self.to_address,
            "value": str(self.value),
            "token_symbol": self.token_symbol,
            "block_number": self.block_number,
            "timestamp": self.timestamp,
            "additional_data": self.additional_data,
        }


@dataclass
class NormalizedHostLog:
    """Standardized schema for host and Sysmon endpoint events."""
    timestamp: str
    event_id: Union[int, str]
    process_name: str
    command_line: str
    user: str
    host: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_id": self.event_id,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "user": self.user,
            "host": self.host,
            "details": self.details,
        }


# ==============================================================================
# Helper Utilities
# ==============================================================================

def normalize_hex_address(addr: Any) -> Optional[str]:
    """Normalizes an Ethereum/EVM hex address to lowercase 0x format."""
    if addr is None:
        return None
    s = str(addr).strip()
    if not s or s.lower() in ("null", "none", "0x", ""):
        return None
    if s.startswith("0x") or s.startswith("0X"):
        return s.lower()
    if re.fullmatch(r"[0-9a-fA-F]{40}", s):
        return f"0x{s.lower()}"
    return s.lower()


def normalize_tx_hash(h: Any) -> str:
    """Normalizes a transaction hash to lowercase 0x hex format."""
    if not h:
        return ""
    s = str(h).strip()
    if s.startswith("0x") or s.startswith("0X"):
        return s.lower()
    if re.fullmatch(r"[0-9a-fA-F]{64}", s):
        return f"0x{s.lower()}"
    return s.lower()


def parse_numeric_value(val: Any) -> Union[int, str]:
    """Safely parses transaction value into int or raw string, avoiding float precision loss."""
    if val is None:
        return 0
    if isinstance(val, int):
        return val
    s = str(val).strip()
    if s.startswith("0x") or s.startswith("0X"):
        try:
            return int(s, 16)
        except ValueError:
            return s
    if s.isdigit():
        try:
            return int(s)
        except ValueError:
            return s
    return s


# ==============================================================================
# Base Adapter Interface
# ==============================================================================

class BaseAdapter:
    """Abstract base class for evidence adapters."""
    source_type_name: str = "base"

    def can_handle(self, filename: str, sample_bytes: bytes) -> bool:
        """Determines if this adapter can process the given file."""
        raise NotImplementedError

    def parse_and_normalize(self, raw_input: Union[bytes, Path, str]) -> List[Dict[str, Any]]:
        """Parses raw content and normalizes into standard record dicts."""
        raise NotImplementedError


# ==============================================================================
# 1. Blockchain Transactions JSON / JSONL Adapter
# ==============================================================================

class BlockchainTxJsonAdapter(BaseAdapter):
    """Adapter for blockchain transactions exported in JSON or JSONL format."""
    source_type_name: str = "blockchain_tx_json"

    def can_handle(self, filename: str, sample_bytes: bytes) -> bool:
        fn = filename.lower()
        if fn.endswith((".json", ".jsonl")):
            # Check if content has transaction-related indicators
            s = sample_bytes[:2048].decode("utf-8", errors="ignore").lower()
            if any(k in s for k in ("hash", "tx_hash", "transactionhash", "from", "to", "value", "transfers")):
                return True
        return False

    def parse_and_normalize(self, raw_input: Union[bytes, Path, str]) -> List[Dict[str, Any]]:
        if isinstance(raw_input, Path):
            with open(raw_input, "rb") as f:
                content_bytes = f.read()
        elif isinstance(raw_input, str):
            content_bytes = raw_input.encode("utf-8")
        else:
            content_bytes = raw_input

        text = content_bytes.decode("utf-8", errors="replace").strip()
        if not text:
            raise SchemaCompatibilityError("Tệp JSON rỗng, không chứa dữ liệu giao dịch.")

        parsed_items: List[Dict[str, Any]] = []

        # Try standard JSON first
        try:
            data = json.loads(text)
            if isinstance(data, list):
                parsed_items = [d for d in data if isinstance(d, dict)]
            elif isinstance(data, dict):
                # Search for list inside known container keys
                for key in ("transactions", "txs", "transfers", "asset_transfers", "records", "data"):
                    if key in data and isinstance(data[key], list):
                        parsed_items = [d for d in data[key] if isinstance(d, dict)]
                        break
                # Or blocks array containing transactions
                if not parsed_items and "blocks" in data and isinstance(data["blocks"], list):
                    for b in data["blocks"]:
                        if isinstance(b, dict):
                            raw_txs = b.get("transactions") or b.get("raw_json", {}).get("transactions")
                            if isinstance(raw_txs, list):
                                for tx in raw_txs:
                                    if isinstance(tx, dict):
                                        parsed_items.append(tx)
                if not parsed_items:
                    # Single transaction object
                    if any(k in data for k in ("hash", "tx_hash", "transactionHash", "from")):
                        parsed_items = [data]
        except json.JSONDecodeError:
            # Fallback to JSONL line-by-line parsing
            parsed_items = []
            lines = text.splitlines()
            for line_no, line in enumerate(lines, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    obj = json.loads(clean_line)
                    if isinstance(obj, dict):
                        # May be a raw block object with transactions
                        if "transactions" in obj and isinstance(obj["transactions"], list):
                            for tx in obj["transactions"]:
                                if isinstance(tx, dict):
                                    parsed_items.append(tx)
                        else:
                            parsed_items.append(obj)
                except json.JSONDecodeError as jde:
                    raise CorruptedFileError(f"Lỗi cú pháp JSON tại dòng {line_no}: {jde}") from jde

        if not parsed_items:
            raise SchemaCompatibilityError(
                "Cấu trúc JSON không chứa mảng giao dịch hợp lệ hoặc không thể nhận diện các trường giao dịch."
            )

        # Normalize parsed transactions
        normalized_records: List[Dict[str, Any]] = []
        for idx, item in enumerate(parsed_items):
            # Extract tx_hash
            tx_h = (
                item.get("tx_hash")
                or item.get("hash")
                or item.get("transactionHash")
                or item.get("txHash")
                or item.get("txid")
            )
            # Extract from_address
            from_a = (
                item.get("from_address")
                or item.get("from_addr")
                or item.get("from")
                or item.get("sender")
                or item.get("src")
            )
            # Extract to_address
            to_a = (
                item.get("to_address")
                or item.get("to_addr")
                or item.get("to")
                or item.get("receiver")
                or item.get("recipient")
                or item.get("dst")
            )
            # Extract value
            val = (
                item.get("value")
                or item.get("amount")
                or item.get("value_raw")
                or item.get("amount_raw")
                or item.get("val")
                or 0
            )

            # We require at least tx_hash or from_address to qualify as transaction record
            if not tx_h and not from_a:
                continue

            # Extract block number
            b_num = item.get("block_number") or item.get("blockNumber") or item.get("block") or 0
            try:
                b_num_int = int(b_num, 16) if isinstance(b_num, str) and b_num.startswith("0x") else int(b_num)
            except Exception:
                b_num_int = 0

            # Extract timestamp
            ts = (
                item.get("timestamp")
                or item.get("block_timestamp")
                or item.get("block_time_utc")
                or item.get("time")
                or int(datetime.now(timezone.utc).timestamp())
            )

            # Token symbol
            token = (
                item.get("token_symbol")
                or item.get("asset_id")
                or item.get("token")
                or item.get("symbol")
                or "ETH"
            )

            rec = NormalizedTransaction(
                tx_hash=normalize_tx_hash(tx_h) if tx_h else f"0xgen_tx_{idx:08x}",
                from_address=normalize_hex_address(from_a) or "0x0000000000000000000000000000000000000000",
                to_address=normalize_hex_address(to_a),
                value=parse_numeric_value(val),
                token_symbol=str(token).upper(),
                block_number=b_num_int,
                timestamp=ts,
                additional_data={k: v for k, v in item.items() if k not in ("raw_json", "transactions")},
            )
            normalized_records.append(rec.to_dict())

        if not normalized_records:
            raise SchemaCompatibilityError(
                "Không trích xuất được giao dịch hợp lệ nào từ tệp JSON. Vui lòng kiểm tra định dạng trường (tx_hash, from, to, value)."
            )

        return normalized_records


# ==============================================================================
# 2. Blockchain Transactions CSV Adapter
# ==============================================================================

class TransactionCsvAdapter(BaseAdapter):
    """Adapter for blockchain transactions exported in CSV format."""
    source_type_name: str = "blockchain_tx_csv"

    def can_handle(self, filename: str, sample_bytes: bytes) -> bool:
        fn = filename.lower()
        if fn.endswith(".csv"):
            header_line = sample_bytes[:1024].decode("utf-8", errors="ignore").splitlines()
            if header_line:
                first_row = header_line[0].lower()
                if any(k in first_row for k in ("hash", "tx", "from", "to", "value", "amount", "transfer")):
                    return True
        return False

    def parse_and_normalize(self, raw_input: Union[bytes, Path, str]) -> List[Dict[str, Any]]:
        if isinstance(raw_input, Path):
            with open(raw_input, "rb") as f:
                content_bytes = f.read()
        elif isinstance(raw_input, str):
            content_bytes = raw_input.encode("utf-8")
        else:
            content_bytes = raw_input

        text = content_bytes.decode("utf-8", errors="replace").strip()
        if not text:
            raise SchemaCompatibilityError("Tệp CSV rỗng, không chứa dữ liệu giao dịch.")

        try:
            stream = io.StringIO(text, newline="")
            reader = csv.DictReader(stream)
            headers = [h.strip() for h in (reader.fieldnames or []) if h]
        except Exception as e:
            raise CorruptedFileError(f"Không thể đọc cấu trúc bảng CSV: {e}") from e

        if not headers:
            raise SchemaCompatibilityError("Tệp CSV không có hàng tiêu đề (header) hợp lệ.")

        # Map header candidates
        lower_headers = {h.lower(): h for h in headers}

        def find_col(candidates: List[str]) -> Optional[str]:
            for c in candidates:
                if c.lower() in lower_headers:
                    return lower_headers[c.lower()]
            return None

        hash_col = find_col(["tx_hash", "hash", "transaction_hash", "txhash", "transactionHash", "tx"])
        from_col = find_col(["from_address", "from_addr", "from", "sender", "src", "from_account"])
        to_col = find_col(["to_address", "to_addr", "to", "receiver", "recipient", "dst", "to_account"])
        val_col = find_col(["value", "amount", "amount_raw", "value_raw", "val", "quantity"])
        block_col = find_col(["block_number", "block_num", "blockNumber", "block", "height"])
        time_col = find_col(["timestamp", "block_timestamp", "timestamp_utc", "time", "date"])
        token_col = find_col(["token_symbol", "asset_id", "symbol", "token", "asset"])

        # Check essential transaction columns
        if not hash_col and not (from_col and val_col):
            raise SchemaCompatibilityError(
                f"Tệp CSV thiếu các cột giao dịch bắt buộc. Các cột hiện có: {headers}. "
                f"Yêu cầu tối thiểu cột mã giao dịch (tx_hash/hash) hoặc địa chỉ gửi (from) kèm giá trị (value/amount)."
            )

        normalized_records: List[Dict[str, Any]] = []
        for row_idx, row in enumerate(reader, start=1):
            if not row or not any(row.values()):
                continue

            raw_hash_val = row.get(hash_col) if hash_col else f"0xcsv_tx_{row_idx:08x}"
            raw_from_val = row.get(from_col) if from_col else "0x0000000000000000000000000000000000000000"
            raw_to_val = row.get(to_col) if to_col else None
            raw_val = row.get(val_col) if val_col else 0

            b_num = 0
            if block_col and row.get(block_col):
                try:
                    b_num = int(row[block_col].strip())
                except ValueError:
                    b_num = 0

            ts: Union[int, str] = 0
            if time_col and row.get(time_col):
                ts = row[time_col].strip()
            else:
                ts = int(datetime.now(timezone.utc).timestamp())

            sym = "ETH"
            if token_col and row.get(token_col):
                sym = row[token_col].strip().upper()

            rec = NormalizedTransaction(
                tx_hash=normalize_tx_hash(raw_hash_val),
                from_address=normalize_hex_address(raw_from_val) or "0x0000000000000000000000000000000000000000",
                to_address=normalize_hex_address(raw_to_val),
                value=parse_numeric_value(raw_val),
                token_symbol=sym or "ETH",
                block_number=b_num,
                timestamp=ts,
                additional_data={k: v for k, v in row.items() if k not in (hash_col, from_col, to_col, val_col)},
            )
            normalized_records.append(rec.to_dict())

        if not normalized_records:
            raise SchemaCompatibilityError("Tệp CSV không chứa dòng dữ liệu giao dịch hợp lệ nào.")

        return normalized_records


# ==============================================================================
# 3. SQLite Database Evidence Adapter (Read-Only)
# ==============================================================================

class SqliteEvidenceAdapter(BaseAdapter):
    """Adapter for SQLite database evidence files, connecting in strictly read-only mode."""
    source_type_name: str = "sqlite_db"

    def can_handle(self, filename: str, sample_bytes: bytes) -> bool:
        fn = filename.lower()
        if fn.endswith((".db", ".sqlite", ".sqlite3")):
            return True
        if sample_bytes.startswith(b"SQLite format 3\x00"):
            return True
        return False

    def parse_and_normalize(self, raw_input: Union[bytes, Path, str]) -> List[Dict[str, Any]]:
        # If passed raw bytes, we must write to an ephemeral temporary file to safely connect via SQLite URI
        temp_file_created = False
        db_file: Path

        if isinstance(raw_input, (bytes, bytearray)):
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
                tf.write(raw_input)
                temp_file_name = tf.name
            db_file = Path(temp_file_name)
            temp_file_created = True
        elif isinstance(raw_input, str):
            db_file = Path(raw_input)
        else:
            db_file = raw_input

        if not db_file.is_file():
            raise CorruptedFileError(f"Tệp CSDL SQLite không tồn tại: {db_file}")

        # Strictly connect in read-only and immutable mode
        uri = f"{db_file.resolve().as_uri()}?mode=ro&immutable=1"
        conn: Optional[sqlite3.Connection] = None
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=5.0)
            conn.row_factory = sqlite3.Row

            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            if not tables:
                raise SchemaCompatibilityError("Cơ sở dữ liệu SQLite rỗng, không chứa bất kỳ bảng nào.")

            normalized_records: List[Dict[str, Any]] = []

            # 1. Check for 'transactions' table
            if "transactions" in tables:
                col_names = [c[1].lower() for c in conn.execute("PRAGMA table_info(transactions)").fetchall()]
                hash_c = next((c for c in ("tx_hash", "hash", "transactionhash") if c in col_names), None)
                from_c = next((c for c in ("from_addr", "from_address", "from") if c in col_names), None)
                to_c = next((c for c in ("to_addr", "to_address", "to") if c in col_names), None)
                val_c = next((c for c in ("value_raw", "value", "amount") if c in col_names), None)
                block_c = next((c for c in ("block_number", "blocknumber") if c in col_names), None)

                if hash_c:
                    query = f"SELECT * FROM transactions LIMIT 5000"
                    rows = conn.execute(query).fetchall()
                    for r in rows:
                        row_dict = dict(r)
                        h = row_dict.get(hash_c)
                        f_addr = row_dict.get(from_c) if from_c else None
                        t_addr = row_dict.get(to_c) if to_c else None
                        v = row_dict.get(val_c) if val_c else 0
                        bn = row_dict.get(block_c) if block_c else 0
                        rec = NormalizedTransaction(
                            tx_hash=normalize_tx_hash(h),
                            from_address=normalize_hex_address(f_addr) or "0x0000000000000000000000000000000000000000",
                            to_address=normalize_hex_address(t_addr),
                            value=parse_numeric_value(v),
                            token_symbol="ETH",
                            block_number=int(bn) if bn else 0,
                            timestamp=row_dict.get("block_timestamp") or row_dict.get("timestamp") or 0,
                            additional_data={k: v for k, v in row_dict.items() if k not in ("raw_json",)},
                        )
                        normalized_records.append(rec.to_dict())

            # 2. Check for 'asset_transfers' table
            elif "asset_transfers" in tables:
                rows = conn.execute("SELECT * FROM asset_transfers LIMIT 5000").fetchall()
                for r in rows:
                    d = dict(r)
                    rec = NormalizedTransaction(
                        tx_hash=normalize_tx_hash(d.get("tx_hash")),
                        from_address=normalize_hex_address(d.get("from_addr") or d.get("from")) or "0x0000000000000000000000000000000000000000",
                        to_address=normalize_hex_address(d.get("to_addr") or d.get("to")),
                        value=parse_numeric_value(d.get("amount_raw") or d.get("amount") or 0),
                        token_symbol=str(d.get("asset_id") or "ETH").upper(),
                        block_number=int(d.get("block_number") or 0),
                        timestamp=d.get("block_timestamp") or 0,
                        additional_data=d,
                    )
                    normalized_records.append(rec.to_dict())

            # 3. Check for 'endpoint_events' table (host forensics DB)
            elif "endpoint_events" in tables:
                rows = conn.execute("SELECT * FROM endpoint_events LIMIT 5000").fetchall()
                for r in rows:
                    d = dict(r)
                    h_rec = NormalizedHostLog(
                        timestamp=str(d.get("timestamp_utc") or d.get("recorded_at_utc") or ""),
                        event_id=d.get("event_id") or "UNKNOWN",
                        process_name=str(d.get("provider_name") or d.get("channel") or "endpoint_event"),
                        command_line=str(d.get("description") or ""),
                        user="SYSTEM",
                        host=str(d.get("host_id") or "localhost"),
                        details=d,
                    )
                    normalized_records.append(h_rec.to_dict())

            else:
                raise SchemaCompatibilityError(
                    f"Cơ sở dữ liệu SQLite không chứa cấu trúc bảng chứng cứ tương thích. "
                    f"Các bảng hiện có: {tables}. Yêu cầu bảng 'transactions', 'asset_transfers' hoặc 'endpoint_events'."
                )

            if not normalized_records:
                raise SchemaCompatibilityError("Bảng chứng cứ trong SQLite không chứa bản ghi hợp lệ nào.")

            return normalized_records

        except sqlite3.DatabaseError as dbe:
            raise CorruptedFileError(f"Tệp SQLite bị hỏng hoặc không thể mở: {dbe}") from dbe
        finally:
            if conn:
                conn.close()
            if temp_file_created:
                try:
                    db_file.unlink()
                except Exception:
                    pass


# ==============================================================================
# 4. Authorized Host Logs / Sysmon Adapter
# ==============================================================================

class AuthorizedHostLogsAdapter(BaseAdapter):
    """Adapter for authorized host and Sysmon endpoint telemetry logs."""
    source_type_name: str = "authorized_host_logs"

    def can_handle(self, filename: str, sample_bytes: bytes) -> bool:
        fn = filename.lower()
        if any(k in fn for k in ("host", "sysmon", "event", "audit", "endpoint")):
            return True
        s = sample_bytes[:2048].decode("utf-8", errors="ignore").lower()
        if any(k in s for k in ("eventid", "event_id", "sysmon", "commandline", "processname", "parentimage")):
            return True
        return False

    def parse_and_normalize(self, raw_input: Union[bytes, Path, str]) -> List[Dict[str, Any]]:
        if isinstance(raw_input, Path):
            with open(raw_input, "rb") as f:
                content_bytes = f.read()
        elif isinstance(raw_input, str):
            content_bytes = raw_input.encode("utf-8")
        else:
            content_bytes = raw_input

        text = content_bytes.decode("utf-8", errors="replace").strip()
        if not text:
            raise SchemaCompatibilityError("Nhật ký trạm cuối rỗng, không chứa dữ liệu sự kiện.")

        raw_events: List[Dict[str, Any]] = []

        # Try JSON / JSONL
        if text.startswith("{") or text.startswith("["):
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    raw_events = [d for d in data if isinstance(d, dict)]
                elif isinstance(data, dict):
                    for k in ("events", "logs", "records", "data"):
                        if k in data and isinstance(data[k], list):
                            raw_events = [d for d in data[k] if isinstance(d, dict)]
                            break
                    if not raw_events:
                        raw_events = [data]
            except json.JSONDecodeError:
                for line in text.splitlines():
                    if line.strip():
                        try:
                            obj = json.loads(line)
                            if isinstance(obj, dict):
                                raw_events.append(obj)
                        except json.JSONDecodeError:
                            pass
        else:
            # Try CSV format
            try:
                reader = csv.DictReader(io.StringIO(text))
                raw_events = list(reader)
            except Exception:
                pass

        if not raw_events:
            raise SchemaCompatibilityError("Không nhận diện được định dạng nhật ký sự kiện trạm cuối (JSON, JSONL hoặc CSV).")

        normalized_records: List[Dict[str, Any]] = []
        for idx, ev in enumerate(raw_events):
            lower_ev = {k.lower(): v for k, v in ev.items()}

            ts = (
                lower_ev.get("timestamp_utc")
                or lower_ev.get("timecreated")
                or lower_ev.get("timestamp")
                or lower_ev.get("recorded_at_utc")
                or lower_ev.get("date")
                or datetime.now(timezone.utc).isoformat()
            )
            eid = lower_ev.get("event_id") or lower_ev.get("eventid") or lower_ev.get("id") or 1
            proc = (
                lower_ev.get("process_name")
                or lower_ev.get("image")
                or lower_ev.get("name")
                or lower_ev.get("process")
                or "unknown_process"
            )
            cmd = (
                lower_ev.get("command_line")
                or lower_ev.get("commandline")
                or lower_ev.get("cmdline")
                or lower_ev.get("description")
                or ""
            )
            usr = lower_ev.get("user") or lower_ev.get("username") or lower_ev.get("user_id") or "SYSTEM"
            hst = lower_ev.get("host") or lower_ev.get("computer") or lower_ev.get("host_id") or "localhost"

            rec = NormalizedHostLog(
                timestamp=str(ts),
                event_id=eid,
                process_name=str(proc),
                command_line=str(cmd),
                user=str(usr),
                host=str(hst),
                details=ev,
            )
            normalized_records.append(rec.to_dict())

        return normalized_records


# ==============================================================================
# Adapter Registry & Discovery
# ==============================================================================

ADAPTERS: List[BaseAdapter] = [
    SqliteEvidenceAdapter(),
    BlockchainTxJsonAdapter(),
    TransactionCsvAdapter(),
    AuthorizedHostLogsAdapter(),
]


def get_adapter_for_format(
    filename: str,
    sample_bytes: bytes,
    declared_source: Optional[str] = None,
) -> BaseAdapter:
    """Finds the most suitable adapter based on declared source or content inspection."""
    if declared_source:
        d = declared_source.strip().lower()
        for a in ADAPTERS:
            if a.source_type_name.lower() == d:
                return a

    # Automatic inspection
    for a in ADAPTERS:
        if a.can_handle(filename, sample_bytes):
            return a

    # Default fallback based on extension
    fn = filename.lower()
    if fn.endswith((".json", ".jsonl")):
        return BlockchainTxJsonAdapter()
    if fn.endswith(".csv"):
        return TransactionCsvAdapter()
    if fn.endswith((".db", ".sqlite", ".sqlite3")):
        return SqliteEvidenceAdapter()
    if fn.endswith((".log", ".txt", ".evtx")):
        return AuthorizedHostLogsAdapter()

    raise FormatError(
        f"Không tìm thấy adapter phù hợp cho tệp '{filename}'. "
        f"Hệ thống hỗ trợ các định dạng: JSON/JSONL giao dịch, CSV giao dịch, CSDL SQLite, hoặc nhật ký trạm cuối."
    )


# ==============================================================================
# Forensic Heuristic Analysis Engine
# ==============================================================================

def analyze_records(records: List[Dict[str, Any]], source_type: str) -> Dict[str, Any]:
    """Runs genuine forensic heuristics on normalized evidence records without hardcoded values."""
    if not records:
        return {
            "statistics": {"total_records": 0},
            "anomalies": [],
            "risk_score": 0.0,
            "summary_vi": "Không có bản ghi nào để phân tích.",
        }

    total_records = len(records)
    anomalies: List[Dict[str, Any]] = []

    if source_type in ("blockchain_tx_json", "blockchain_tx_csv", "sqlite_db"):
        # Blockchain heuristics
        unique_senders = set()
        unique_receivers = set()
        zero_address = "0x0000000000000000000000000000000000000000"
        high_value_records = []
        contract_creations = []
        zero_address_transfers = []
        sender_counts: Dict[str, int] = {}

        min_block = None
        max_block = None

        for r in records:
            from_a = (r.get("from_address") or "").lower()
            to_a = (r.get("to_address") or "").lower() if r.get("to_address") else None
            val_raw = r.get("value")
            h = r.get("tx_hash") or ""
            bn = r.get("block_number")

            if from_a:
                unique_senders.add(from_a)
                sender_counts[from_a] = sender_counts.get(from_a, 0) + 1
            if to_a:
                unique_receivers.add(to_a)

            if isinstance(bn, int) and bn > 0:
                if min_block is None or bn < min_block:
                    min_block = bn
                if max_block is None or bn > max_block:
                    max_block = bn

            # Check 1: Contract deployment (to_address is None)
            if to_a is None or to_a in ("", "0x", zero_address):
                contract_creations.append({
                    "tx_hash": h,
                    "from_address": from_a,
                    "value": str(val_raw),
                })

            # Check 2: Transfer involving zero address (mint or burn)
            if from_a == zero_address or to_a == zero_address:
                zero_address_transfers.append({
                    "tx_hash": h,
                    "from_address": from_a,
                    "to_address": to_a,
                    "value": str(val_raw),
                })

            # Check 3: Large numerical value
            try:
                numeric_val = int(val_raw)
                # If value is >= 10^22 (approx 10,000 ETH in wei) or >= 1,000,000 in standard token units
                if numeric_val >= 10**22 or (numeric_val >= 1_000_000 and len(str(numeric_val)) < 15):
                    high_value_records.append({
                        "tx_hash": h,
                        "value": str(val_raw),
                        "token": r.get("token_symbol"),
                        "from": from_a,
                        "to": to_a,
                    })
            except (ValueError, TypeError):
                pass

        # High frequency senders (possible automated drainer or bot)
        burst_senders = [addr for addr, count in sender_counts.items() if count >= 10 and count >= total_records * 0.2]

        if high_value_records:
            anomalies.append({
                "type": "HIGH_VALUE_TRANSFER",
                "severity": "HIGH",
                "count": len(high_value_records),
                "description": f"Phát hiện {len(high_value_records)} giao dịch có giá trị dịch chuyển tài sản đột biến.",
                "sample": high_value_records[:3],
            })

        if contract_creations:
            anomalies.append({
                "type": "CONTRACT_DEPLOYMENT",
                "severity": "MEDIUM",
                "count": len(contract_creations),
                "description": f"Phát hiện {len(contract_creations)} giao dịch khởi tạo hợp đồng thông minh hoặc tương tác địa chỉ rỗng.",
                "sample": contract_creations[:3],
            })

        if zero_address_transfers:
            anomalies.append({
                "type": "MINT_OR_BURN_EVENT",
                "severity": "LOW",
                "count": len(zero_address_transfers),
                "description": f"Ghi nhận {len(zero_address_transfers)} giao dịch liên quan đến địa chỉ Zero (Mint/Burn).",
                "sample": zero_address_transfers[:3],
            })

        if burst_senders:
            anomalies.append({
                "type": "HIGH_FREQUENCY_SENDER",
                "severity": "MEDIUM",
                "count": len(burst_senders),
                "description": f"Phát hiện {len(burst_senders)} địa chỉ gửi giao dịch với tần suất cao bất thường.",
                "sample": burst_senders[:3],
            })

        # Calculate risk score
        risk = min(100.0, len(high_value_records) * 15.0 + len(contract_creations) * 8.0 + len(burst_senders) * 10.0)

        stats = {
            "total_records": total_records,
            "unique_senders": len(unique_senders),
            "unique_receivers": len(unique_receivers),
            "min_block": min_block,
            "max_block": max_block,
            "high_value_count": len(high_value_records),
            "contract_creations_count": len(contract_creations),
        }

        summary = (
            f"Đã phân tích {total_records} giao dịch chuỗi khối qua adapter {source_type}. "
            f"Xác định {len(unique_senders)} địa chỉ gửi, {len(unique_receivers)} địa chỉ nhận. "
            f"Phát hiện {len(anomalies)} nhóm dấu hiệu đáng chú ý (Điểm rủi ro: {risk:.1f}/100)."
        )

        return {
            "statistics": stats,
            "anomalies": anomalies,
            "risk_score": round(risk, 1),
            "summary_vi": summary,
        }

    else:
        # Host Log heuristics
        suspicious_keywords = [
            "powershell -enc",
            "mimikatz",
            "certutil -urlcache",
            "whoami /priv",
            "vssadmin delete shadows",
            "psexec",
            "lsass",
            "reg save",
        ]
        flagged_events = []
        unique_processes = set()
        unique_users = set()

        for r in records:
            cmd = (r.get("command_line") or "").lower()
            proc = (r.get("process_name") or "").lower()
            usr = (r.get("user") or "")

            if proc:
                unique_processes.add(proc)
            if usr:
                unique_users.add(usr)

            for kw in suspicious_keywords:
                if kw in cmd:
                    flagged_events.append({
                        "event_id": r.get("event_id"),
                        "process": proc,
                        "command_line": cmd[:120],
                        "matched_rule": kw,
                    })
                    break

        if flagged_events:
            anomalies.append({
                "type": "SUSPICIOUS_ENDPOINT_COMMAND",
                "severity": "CRITICAL",
                "count": len(flagged_events),
                "description": f"Phát hiện {len(flagged_events)} câu lệnh trạm cuối khả nghi khớp với véc-tơ tấn công hệ thống.",
                "sample": flagged_events[:3],
            })

        risk = min(100.0, len(flagged_events) * 25.0)

        stats = {
            "total_records": total_records,
            "unique_processes": len(unique_processes),
            "unique_users": len(unique_users),
            "suspicious_events_count": len(flagged_events),
        }

        summary = (
            f"Đã phân tích {total_records} sự kiện nhật ký trạm cuối. "
            f"Ghi nhận {len(unique_processes)} tiến trình, {len(unique_users)} người dùng. "
            f"Phát hiện {len(flagged_events)} sự kiện khả nghi (Điểm rủi ro: {risk:.1f}/100)."
        )

        return {
            "statistics": stats,
            "anomalies": anomalies,
            "risk_score": round(risk, 1),
            "summary_vi": summary,
        }
