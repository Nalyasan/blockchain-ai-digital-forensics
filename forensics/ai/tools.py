"""P5 AI Investigator Authorized Forensics Tools & Execution Guardrails.

This module provides the six authorized forensics tools and security guardrails
for the P5 AI Investigator component, built for Pydantic AI and Google Gemini.

Authorized Tools:
1. `get_alerts`: Read-only query for rule alerts with parsed evidence references.
2. `get_tx`: Read-only transaction header and associated asset transfer details.
3. `get_address_history`: Chronological asset transfer history for a specified address.
4. `get_counterparties`: Aggregated counterparty transfer activity with exact integer volumes.
5. `get_timeline`: Multi-entity chronological timeline combining blocks, transfers, and alerts.
6. `collect_missing_range`: Bounded blockchain block collection into isolated staging only.

Security Guarantees:
- Strict Authorization Whitelist: Only the 6 authorized tools may be dispatched;
  unauthorized invocations immediately raise `UnauthorizedToolError`.
- Strict Read-Only Preservation: Five query tools operate strictly read-only against
  production database (`real_p4.db`).
- Exact Integer Precision: All amounts (`amount_raw`, `volume_sent_raw`, `total_volume_raw`)
  are preserved as exact arbitrary-precision integer strings without SQLite float conversion.
- Bounded Staging Collection: `collect_missing_range` enforces `<= 20` blocks inclusive,
  rejects 21+ blocks with `RangeLimitExceeded`, enforces max 2 calls per session with
  `SessionLimitExceeded`, and rejects canonical database targets with
  `ProductionDatabaseMutationError`.
- Step Budget Enforcement: Hard ceiling of `MAX_AI_TOOL_STEPS = 5` enforced by
  `ToolBudgetManager`, counting attempted calls separately from successful calls.
- Thread Safety: SQLite staging helper provides `check_same_thread=False` for Pydantic AI
  worker thread compatibility.
- G5-02 Invariant Compliance: Strictly zero state-mutating replacement SQL statements.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Union

from forensics.ai.db_readonly import get_readonly_connection

logger = logging.getLogger("forensics.ai.tools")

DEFAULT_BENCHMARK_DB_PATH: Path = Path("D:/Projest/p6_public_benchmark/data/benchmark_p6.db")

__all__ = [
    "AUTHORIZED_TOOLS",
    "CASE_DEFINITIONS",
    "DEFAULT_BENCHMARK_DB_PATH",
    "MAX_AI_TOOL_STEPS",
    "MAX_BLOCKS_PER_COLLECT",
    "MAX_COLLECT_CALLS_PER_SESSION",
    "P6_AUTHORIZED_TOOLS",
    "ProductionDatabaseMutationError",
    "RangeLimitExceeded",
    "RULE_ALIASES",
    "SessionLimitExceeded",
    "ToolBudgetExceeded",
    "ToolBudgetManager",
    "ToolCallBudgetTracker",
    "UnauthorizedToolError",
    "collect_missing_range",
    "execute_guarded_tool",
    "execute_tool_with_guardrails",
    "get_address_history",
    "get_alerts",
    "get_counterparties",
    "get_staging_connection",
    "get_threat_intel",
    "get_timeline",
    "get_tx",
    "init_staging_tables",
    "validate_block_range",
    "verify_staging_database",
]

# Constants
MAX_AI_TOOL_STEPS: int = 5
MAX_COLLECT_CALLS_PER_SESSION: int = 2
MAX_BLOCKS_PER_COLLECT: int = 20

AUTHORIZED_TOOLS: frozenset[str] = frozenset({
    "get_alerts",
    "get_tx",
    "get_address_history",
    "get_counterparties",
    "get_timeline",
    "collect_missing_range",
})

P6_AUTHORIZED_TOOLS: frozenset[str] = frozenset(AUTHORIZED_TOOLS | {"get_threat_intel"})

# Canonical rule aliases matching Phase 4 Rule Engine
RULE_ALIASES: dict[str, str] = {
    "r1": "large_transfer",
    "r2": "high_frequency",
    "r3": "fan_in_out",
    "r4": "rapid_pass_through",
    "large_transfer": "large_transfer",
    "high_frequency": "high_frequency",
    "fan_in_out": "fan_in_out",
    "rapid_pass_through": "rapid_pass_through",
}

# Known case time and block windows for real Ethereum incident evaluation
CASE_DEFINITIONS: dict[str, dict[str, Any]] = {
    "euler": {
        "name": "Euler Finance Exploit",
        "start_block": 16817990,
        "end_block": 16818110,
        "start_timestamp": 1678697300,  # ~2023-03-13 08:48 UTC
        "end_timestamp": 1678700000,
        "primary_asset": "0x6b175474e89094c44da98b954eedeac495271d0f",  # DAI
    },
    "euler_finance": {
        "name": "Euler Finance Exploit",
        "start_block": 16817990,
        "end_block": 16818110,
        "start_timestamp": 1678697300,
        "end_timestamp": 1678700000,
        "primary_asset": "0x6b175474e89094c44da98b954eedeac495271d0f",
    },
    "curve": {
        "name": "Curve / Alchemix Vyper Reentrancy Exploit",
        "start_block": 17806700,
        "end_block": 17852000,
        "start_timestamp": 1690731000,  # 2023-07-30 15:30 UTC
        "end_timestamp": 1692000000,
        "primary_asset": "0x0100546f2cd4c9d97f798ffc9755e47865ff7ee6",  # alETH
    },
    "alchemix": {
        "name": "Curve / Alchemix Vyper Reentrancy Exploit",
        "start_block": 17806700,
        "end_block": 17852000,
        "start_timestamp": 1690731000,
        "end_timestamp": 1692000000,
        "primary_asset": "0x0100546f2cd4c9d97f798ffc9755e47865ff7ee6",
    },
    "euler-finance": {
        "name": "Euler Finance Exploit",
        "start_block": 16817990,
        "end_block": 16818110,
        "start_timestamp": 1678697300,
        "end_timestamp": 1678700000,
        "primary_asset": "0x6b175474e89094c44da98b954eedeac495271d0f",
    },
    "curve-alchemix": {
        "name": "Curve / Alchemix Vyper Reentrancy Exploit",
        "start_block": 17806700,
        "end_block": 17852000,
        "start_timestamp": 1690731000,
        "end_timestamp": 1692000000,
        "primary_asset": "0x0100546f2cd4c9d97f798ffc9755e47865ff7ee6",
    },
    "curve_alchemix": {
        "name": "Curve / Alchemix Vyper Reentrancy Exploit",
        "start_block": 17806700,
        "end_block": 17852000,
        "start_timestamp": 1690731000,
        "end_timestamp": 1692000000,
        "primary_asset": "0x0100546f2cd4c9d97f798ffc9755e47865ff7ee6",
    },
}


# ==============================================================================
# Custom Exceptions
# ==============================================================================


class RangeLimitExceeded(ValueError):
    """Raised when collect_missing_range requests more than 20 blocks inclusive."""


class SessionLimitExceeded(RuntimeError):
    """Raised when collect_missing_range is called more than 2 times in a session."""


class UnauthorizedToolError(PermissionError):
    """Raised when an unauthorized tool invocation is attempted."""


class ToolBudgetExceeded(RuntimeError):
    """Raised when total attempted tool calls reach or exceed MAX_AI_TOOL_STEPS (5)."""


class ProductionDatabaseMutationError(PermissionError):
    """Raised when an attempt is made to collect into a production/canonical database."""


# ==============================================================================
# Budget Management & Audit Logging
# ==============================================================================


@dataclass
class ToolCallBudgetTracker:
    """Tracks and enforces tool step budgets and session invocation limits."""

    max_steps: int = MAX_AI_TOOL_STEPS
    max_collect_calls: int = MAX_COLLECT_CALLS_PER_SESSION
    attempted_tool_calls: int = 0
    successful_tool_calls: int = 0
    failed_tool_calls: int = 0
    collect_calls: int = 0
    budget_exhausted: bool = False
    tool_calls: list[dict[str, Any]] = field(default_factory=list)

    def record_attempt(self, tool_name: str, args: dict[str, Any]) -> int:
        """Records an attempted tool invocation before execution.

        Raises ToolBudgetExceeded if budget is already exhausted.
        """
        if self.attempted_tool_calls >= self.max_steps:
            self.budget_exhausted = True
            entry = {
                "step": self.attempted_tool_calls + 1,
                "tool_name": tool_name,
                "arguments": args,
                "status": "budget_exceeded",
                "duration_ms": 0.0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "result_summary": None,
                "error": f"ToolBudgetExceeded: MAX_AI_TOOL_STEPS ({self.max_steps}) exceeded",
            }
            self.tool_calls.append(entry)
            raise ToolBudgetExceeded(
                f"Tool execution budget exhausted: MAX_AI_TOOL_STEPS={self.max_steps}"
            )

        self.attempted_tool_calls += 1
        return self.attempted_tool_calls

    def record_success(
        self,
        step_num: int,
        tool_name: str,
        args: dict[str, Any],
        result_summary: Any,
        duration_ms: float,
    ) -> None:
        """Records a successful tool execution."""
        self.successful_tool_calls += 1
        entry = {
            "step": step_num,
            "tool_name": tool_name,
            "arguments": args,
            "status": "success",
            "duration_ms": round(duration_ms, 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result_summary": result_summary,
            "error": None,
        }
        self.tool_calls.append(entry)

    def record_failure(
        self,
        step_num: int,
        tool_name: str,
        args: dict[str, Any],
        error: Exception | str,
        status: str = "failed",
        duration_ms: float = 0.0,
    ) -> None:
        """Records a failed or rejected tool execution."""
        self.failed_tool_calls += 1
        entry = {
            "step": step_num,
            "tool_name": tool_name,
            "arguments": args,
            "status": status,
            "duration_ms": round(duration_ms, 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result_summary": None,
            "error": f"{type(error).__name__}: {error}" if isinstance(error, Exception) else str(error),
        }
        self.tool_calls.append(entry)

    def to_tool_calls_log(self) -> str:
        """Serializes structured tool calls log for analysis_runs.tool_calls_log."""
        payload = {
            "summary": {
                "max_steps": self.max_steps,
                "attempted_steps": self.attempted_tool_calls,
                "successful_steps": self.successful_tool_calls,
                "failed_steps": self.failed_tool_calls,
                "collect_calls": self.collect_calls,
                "max_collect_calls": self.max_collect_calls,
                "budget_exhausted": self.budget_exhausted,
            },
            "calls": self.tool_calls,
        }
        return json.dumps(payload, indent=2, sort_keys=True)


class ToolBudgetManager(ToolCallBudgetTracker):
    """Alias and primary manager class for tool execution budget and limits."""


# ==============================================================================
# Helper Functions
# ==============================================================================


def _parse_timestamp(val: Union[int, str, None]) -> int | None:
    """Helper to convert int, float or ISO 8601 string into unix epoch integer."""
    if val is None:
        return None
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str):
        v = val.strip()
        if not v:
            return None
        if v.isdigit():
            return int(v)
        try:
            if v.endswith("Z"):
                v = v[:-1] + "+00:00"
            dt = datetime.fromisoformat(v)
            return int(dt.timestamp())
        except ValueError:
            return None
    return None


def validate_block_range(start_block: int, end_block: int) -> int:
    """Validates requested block range according to M2 rules:

    - start_block and end_block must be integers (not bools, strings, etc.)
    - start_block >= 0 and end_block >= 0
    - start_block <= end_block
    - (end_block - start_block + 1) <= 20

    Returns:
        The block count (1..20) if valid.

    Raises:
        TypeError: If block arguments are not integer types.
        ValueError: If block numbers are negative or inverted.
        RangeLimitExceeded: If block range exceeds 20 blocks inclusive.
    """
    if type(start_block) is not int or type(end_block) is not int:
        raise TypeError(
            f"Block numbers must be integers, got start_block={type(start_block).__name__}, "
            f"end_block={type(end_block).__name__}"
        )

    if start_block < 0 or end_block < 0:
        raise ValueError(
            f"Block numbers must be non-negative: start_block={start_block}, end_block={end_block}"
        )

    if start_block > end_block:
        raise ValueError(
            f"Invalid block range: start_block ({start_block}) must be <= end_block ({end_block})"
        )

    count = end_block - start_block + 1
    if count > MAX_BLOCKS_PER_COLLECT:
        raise RangeLimitExceeded(
            f"Range limit exceeded: requested {count} blocks ({start_block}..{end_block}), "
            f"maximum allowed is {MAX_BLOCKS_PER_COLLECT} blocks inclusive"
        )

    return count


def verify_staging_database(conn: sqlite3.Connection) -> None:
    """Verifies that conn is an isolated staging database and NOT a canonical DB."""
    if not isinstance(conn, sqlite3.Connection):
        raise TypeError(f"staging_db must be an sqlite3.Connection, got {type(conn).__name__}")

    try:
        row = conn.execute("PRAGMA query_only;").fetchone()
        if row and row[0] == 1:
            raise ProductionDatabaseMutationError(
                "Cannot collect into read-only connection: staging database must be an isolated writable database"
            )
    except Exception as e:
        if isinstance(e, ProductionDatabaseMutationError):
            raise
        raise ProductionDatabaseMutationError(f"Database cannot accept writes: {e}") from e

    try:
        row = conn.execute("PRAGMA database_list;").fetchone()
        if row and row[2]:
            db_file = Path(row[2]).name.lower()
            if "real_p4" in db_file or "canonical" in db_file:
                raise ProductionDatabaseMutationError(
                    f"Refusing to write to protected production database: {row[2]}"
                )
    except sqlite3.OperationalError:
        pass


def init_staging_tables(conn: sqlite3.Connection) -> None:
    """Initializes tables in isolated staging database if not already present."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS blocks(
            chain_id INT, number INT, hash TEXT, parent_hash TEXT, block_timestamp INT,
            block_time_utc TEXT, first_observed_at TEXT, collected_at TEXT, status TEXT DEFAULT 'staging',
            raw_json TEXT, raw_sha256 TEXT, synthetic INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY(chain_id, hash)
        );
        CREATE TABLE IF NOT EXISTS transactions(
            chain_id INT, tx_hash TEXT, block_hash TEXT, block_number INT, tx_index INT,
            from_addr TEXT, to_addr TEXT, value_raw TEXT, nonce INT, input TEXT, raw_json TEXT, raw_sha256 TEXT,
            PRIMARY KEY(chain_id, tx_hash, block_hash)
        );
        CREATE TABLE IF NOT EXISTS receipts(
            chain_id INT, tx_hash TEXT, block_hash TEXT, status INT, gas_used INT,
            contract_address TEXT, raw_json TEXT, raw_sha256 TEXT,
            PRIMARY KEY(chain_id, tx_hash, block_hash)
        );
        CREATE TABLE IF NOT EXISTS logs(
            chain_id INT, block_hash TEXT, log_index INT, tx_hash TEXT, address TEXT,
            topics TEXT, data TEXT, raw_json TEXT,
            PRIMARY KEY(chain_id, block_hash, log_index)
        );
        CREATE TABLE IF NOT EXISTS asset_transfers(
            transfer_id INTEGER PRIMARY KEY AUTOINCREMENT,
            chain_id INT, block_number INT, block_hash TEXT, block_timestamp INT, tx_hash TEXT, log_index INT,
            asset_id TEXT, from_addr TEXT, to_addr TEXT, amount_raw TEXT, synthetic INTEGER NOT NULL DEFAULT 1,
            UNIQUE(chain_id, block_hash, tx_hash, log_index)
        );
        CREATE TABLE IF NOT EXISTS collector_runs(
            run_id TEXT PRIMARY KEY, rpc_label TEXT, chain_id INT, synthetic INT, mode TEXT,
            start_block INT, end_block INT, blocks_count INT, txs_count INT,
            blocks_per_sec REAL, txs_per_sec REAL, retries_count INT, gaps_count INT,
            watch_filter TEXT, status TEXT, started_at TEXT, ended_at TEXT, commit_hash TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, action TEXT, object_ref TEXT, metadata TEXT
        );
    """)
    conn.commit()


def get_staging_connection(db_path: Union[str, Path, None] = None) -> sqlite3.Connection:
    """Creates an isolated staging SQLite connection compatible with AnyIO worker threads.

    Args:
        db_path: Optional path to SQLite file. If omitted, uses in-memory database.

    Returns:
        sqlite3.Connection initialized with staging tables and check_same_thread=False.
    """
    target = ":memory:" if db_path is None else str(db_path)
    conn = sqlite3.connect(target, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_staging_tables(conn)
    return conn


# ==============================================================================
# Authorized Tool 1: get_alerts (Read-Only)
# ==============================================================================


def get_alerts(
    db: sqlite3.Connection,
    rule_id: str | None = None,
    severity: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Query alerts from database and parse evidence_refs into Python structures.

    Args:
        db: Strictly read-only SQLite connection.
        rule_id: Optional rule identifier or alias (e.g. 'large_transfer', 'r1').
        severity: Optional severity level (e.g. 'HIGH', 'MEDIUM').
        limit: Max number of alerts to return (default 50, clamped to 1..1000).

    Returns:
        List of alert dictionaries with parsed evidence_refs and exact amount_raw.
    """
    bounded_limit = max(1, min(int(limit), 1000))
    query_parts = ["SELECT * FROM alerts WHERE 1=1"]
    params: list[Any] = []

    if rule_id is not None:
        raw_rule = str(rule_id).strip().lower()
        canon_rule = RULE_ALIASES.get(raw_rule, raw_rule)
        query_parts.append("AND LOWER(rule_id) = ?")
        params.append(canon_rule)

    if severity is not None:
        sev = str(severity).strip().upper()
        query_parts.append("AND UPPER(severity) = ?")
        params.append(sev)

    query_parts.append("ORDER BY window_start ASC, created_at ASC LIMIT ?")
    params.append(bounded_limit)

    sql = " ".join(query_parts)
    cursor = db.cursor()
    cursor.execute(sql, params)
    rows = cursor.fetchall()

    results: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        raw_refs = item.get("evidence_refs")
        if isinstance(raw_refs, str) and raw_refs.strip():
            try:
                parsed_refs = json.loads(raw_refs)
                if isinstance(parsed_refs, list):
                    for ref in parsed_refs:
                        if isinstance(ref, dict) and "amount_raw" in ref and ref["amount_raw"] is not None:
                            ref["amount_raw"] = str(ref["amount_raw"])
                    item["evidence_refs"] = parsed_refs
                else:
                    item["evidence_refs"] = []
            except Exception:
                item["evidence_refs"] = []
        elif raw_refs is None:
            item["evidence_refs"] = []
        results.append(item)

    return results


# ==============================================================================
# Authorized Tool 2: get_tx (Read-Only)
# ==============================================================================


def get_tx(db: sqlite3.Connection, tx_hash: str) -> dict[str, Any] | None:
    """Query transaction metadata and its associated asset transfers.

    Args:
        db: Strictly read-only SQLite connection.
        tx_hash: Transaction hash string (hex with or without 0x prefix).

    Returns:
        Dictionary containing transaction details and list of asset transfers,
        or None if no transaction or transfer record exists for tx_hash.
    """
    if not tx_hash or not isinstance(tx_hash, str):
        return None

    norm_tx = tx_hash.strip().lower()
    cursor = db.cursor()

    cursor.execute(
        "SELECT * FROM transactions WHERE LOWER(tx_hash) = ? LIMIT 1",
        (norm_tx,),
    )
    tx_row = cursor.fetchone()

    cursor.execute(
        """
        SELECT transfer_id, chain_id, block_number, block_hash, block_timestamp,
               tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic
        FROM asset_transfers
        WHERE LOWER(tx_hash) = ?
        ORDER BY log_index ASC
        """,
        (norm_tx,),
    )
    transfer_rows = cursor.fetchall()

    transfers: list[dict[str, Any]] = []
    for r in transfer_rows:
        t = dict(r)
        if t.get("amount_raw") is not None:
            t["amount_raw"] = str(t["amount_raw"])
        transfers.append(t)

    if not tx_row and not transfers:
        return None

    if tx_row:
        res = dict(tx_row)
        if res.get("value_raw") is not None:
            res["value_raw"] = str(res["value_raw"])
        res["transfers"] = transfers
        return res

    first = transfers[0]
    return {
        "chain_id": first.get("chain_id"),
        "tx_hash": first.get("tx_hash"),
        "block_hash": first.get("block_hash"),
        "block_number": first.get("block_number"),
        "tx_index": None,
        "from_addr": None,
        "to_addr": None,
        "value_raw": "0",
        "nonce": None,
        "input": None,
        "raw_json": None,
        "raw_sha256": None,
        "transfers": transfers,
    }


# ==============================================================================
# Authorized Tool 3: get_address_history (Read-Only)
# ==============================================================================


def get_address_history(
    db: sqlite3.Connection,
    address: str,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Query chronological asset transfer history involving the given address.

    Args:
        db: Strictly read-only SQLite connection.
        address: Ethereum address string (case-insensitive).
        limit: Max number of transfer records to return (default 100, clamped 1..1000).

    Returns:
        List of asset transfer dictionaries sorted chronologically (block_number ASC, log_index ASC).
    """
    if not address or not isinstance(address, str):
        return []

    norm_addr = address.strip().lower()
    bounded_limit = max(1, min(int(limit), 1000))

    cursor = db.cursor()
    cursor.execute(
        """
        SELECT transfer_id, chain_id, block_number, block_hash, block_timestamp,
               tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic
        FROM asset_transfers
        WHERE LOWER(from_addr) = ? OR LOWER(to_addr) = ?
        ORDER BY block_number ASC, log_index ASC
        LIMIT ?
        """,
        (norm_addr, norm_addr, bounded_limit),
    )
    rows = cursor.fetchall()

    results: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        if d.get("amount_raw") is not None:
            d["amount_raw"] = str(d["amount_raw"])
        results.append(d)

    return results


# ==============================================================================
# Authorized Tool 4: get_counterparties (Read-Only)
# ==============================================================================


def get_counterparties(
    db: sqlite3.Connection,
    address: str,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Query counterparties and aggregate transfer volumes for the given address.

    Preserves exact arbitrary-precision integer string amounts without floating point
    precision loss or overflow.

    Args:
        db: Strictly read-only SQLite connection.
        address: Ethereum address string (case-insensitive).
        limit: Max number of counterparties to return (default 50, clamped 1..500).

    Returns:
        List of counterparty aggregate dictionaries sorted by total transfer activity.
    """
    if not address or not isinstance(address, str):
        return []

    norm_addr = address.strip().lower()
    bounded_limit = max(1, min(int(limit), 500))

    cursor = db.cursor()
    cursor.execute(
        """
        SELECT from_addr, to_addr, asset_id, amount_raw, block_number, tx_hash
        FROM asset_transfers
        WHERE LOWER(from_addr) = ? OR LOWER(to_addr) = ?
        """,
        (norm_addr, norm_addr),
    )
    rows = cursor.fetchall()

    aggregates: dict[str, dict[str, Any]] = {}

    for r in rows:
        f = (r["from_addr"] or "").lower()
        t = (r["to_addr"] or "").lower()
        asset = r["asset_id"] or "UNKNOWN"
        raw_amt_str = r["amount_raw"]
        amt_int = int(raw_amt_str) if (raw_amt_str and str(raw_amt_str).isdigit()) else 0
        tx = r["tx_hash"]

        is_sent = (f == norm_addr)
        is_recv = (t == norm_addr)

        if is_sent:
            cp = t
            if cp not in aggregates:
                aggregates[cp] = {
                    "counterparty": cp,
                    "sent_count": 0,
                    "received_count": 0,
                    "volume_sent_int": 0,
                    "volume_received_int": 0,
                    "assets": set(),
                    "tx_hashes": set(),
                }
            aggregates[cp]["sent_count"] += 1
            aggregates[cp]["volume_sent_int"] += amt_int
            aggregates[cp]["assets"].add(asset)
            if tx:
                aggregates[cp]["tx_hashes"].add(tx)

        if is_recv:
            cp = f
            if cp not in aggregates:
                aggregates[cp] = {
                    "counterparty": cp,
                    "sent_count": 0,
                    "received_count": 0,
                    "volume_sent_int": 0,
                    "volume_received_int": 0,
                    "assets": set(),
                    "tx_hashes": set(),
                }
            aggregates[cp]["received_count"] += 1
            aggregates[cp]["volume_received_int"] += amt_int
            aggregates[cp]["assets"].add(asset)
            if tx:
                aggregates[cp]["tx_hashes"].add(tx)

    sorted_items = sorted(
        aggregates.values(),
        key=lambda x: (x["sent_count"] + x["received_count"], x["volume_sent_int"] + x["volume_received_int"]),
        reverse=True,
    )

    results: list[dict[str, Any]] = []
    for item in sorted_items[:bounded_limit]:
        vol_sent = item["volume_sent_int"]
        vol_recv = item["volume_received_int"]
        results.append({
            "counterparty": item["counterparty"],
            "total_transfers": item["sent_count"] + item["received_count"],
            "sent_count": item["sent_count"],
            "received_count": item["received_count"],
            "volume_sent_raw": str(vol_sent),
            "volume_received_raw": str(vol_recv),
            "total_volume_raw": str(vol_sent + vol_recv),
            "assets": sorted(list(item["assets"])),
            "unique_txs": len(item["tx_hashes"]),
        })

    return results


# ==============================================================================
# Authorized Tool 5: get_timeline (Read-Only)
# ==============================================================================


def get_timeline(
    db: sqlite3.Connection,
    case_id: str | None = None,
    start_time: int | str | None = None,
    end_time: int | str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Query chronological timeline joining blocks, asset transfers, and alerts.

    Args:
        db: Strictly read-only SQLite connection.
        case_id: Optional case identifier ('euler', 'curve', etc.).
        start_time: Optional start time (unix epoch integer or ISO 8601 string).
        end_time: Optional end time (unix epoch integer or ISO 8601 string).
        limit: Max events to return (default 100, clamped 1..1000).

    Returns:
        List of chronological event dicts with event_type ('block', 'transfer', 'alert').
    """
    bounded_limit = max(1, min(int(limit), 1000))
    ts_start = _parse_timestamp(start_time)
    ts_end = _parse_timestamp(end_time)

    block_min: int | None = None
    block_max: int | None = None
    asset_filter: str | None = None

    if case_id is not None:
        c_key = str(case_id).strip().lower()
        c_norm = c_key.replace("-", "_")
        c_info = CASE_DEFINITIONS.get(c_key) or CASE_DEFINITIONS.get(c_norm)
        if c_info is None:
            if "euler" in c_norm:
                c_info = CASE_DEFINITIONS["euler"]
            elif "curve" in c_norm or "alchemix" in c_norm:
                c_info = CASE_DEFINITIONS["curve"]
        if c_info is not None:
            block_min = c_info.get("start_block")
            block_max = c_info.get("end_block")
            if ts_start is None:
                ts_start = c_info.get("start_timestamp")
            if ts_end is None:
                ts_end = c_info.get("end_timestamp")
            asset_filter = c_info.get("primary_asset")

    # 1. Fetch Blocks
    block_clauses = ["1=1"]
    block_params: list[Any] = []
    if block_min is not None:
        block_clauses.append("number >= ?")
        block_params.append(block_min)
    if block_max is not None:
        block_clauses.append("number <= ?")
        block_params.append(block_max)
    if ts_start is not None:
        block_clauses.append("block_timestamp >= ?")
        block_params.append(ts_start)
    if ts_end is not None:
        block_clauses.append("block_timestamp <= ?")
        block_params.append(ts_end)

    sql_blocks = f"""
        SELECT number, hash, block_timestamp, block_time_utc, status
        FROM blocks
        WHERE {' AND '.join(block_clauses)}
        ORDER BY number ASC
        LIMIT ?
    """
    block_params.append(bounded_limit)
    cursor = db.cursor()
    cursor.execute(sql_blocks, block_params)
    block_rows = cursor.fetchall()

    # 2. Fetch Asset Transfers
    tx_clauses = ["1=1"]
    tx_params: list[Any] = []
    if block_min is not None:
        tx_clauses.append("t.block_number >= ?")
        tx_params.append(block_min)
    if block_max is not None:
        tx_clauses.append("t.block_number <= ?")
        tx_params.append(block_max)
    if ts_start is not None:
        tx_clauses.append("t.block_timestamp >= ?")
        tx_params.append(ts_start)
    if ts_end is not None:
        tx_clauses.append("t.block_timestamp <= ?")
        tx_params.append(ts_end)
    if asset_filter is not None:
        tx_clauses.append("LOWER(t.asset_id) = ?")
        tx_params.append(asset_filter.lower())

    sql_txs = f"""
        SELECT t.transfer_id, t.chain_id, t.block_number, t.block_hash, t.block_timestamp,
               t.tx_hash, t.log_index, t.asset_id, t.from_addr, t.to_addr, t.amount_raw,
               b.block_time_utc
        FROM asset_transfers t
        LEFT JOIN blocks b ON t.chain_id = b.chain_id AND t.block_hash = b.hash
        WHERE {' AND '.join(tx_clauses)}
        ORDER BY t.block_number ASC, t.log_index ASC
        LIMIT ?
    """
    tx_params.append(bounded_limit)
    cursor.execute(sql_txs, tx_params)
    transfer_rows = cursor.fetchall()

    # 3. Fetch Alerts
    alert_clauses = ["1=1"]
    alert_params: list[Any] = []
    if asset_filter is not None:
        alert_clauses.append("LOWER(asset_id) = ?")
        alert_params.append(asset_filter.lower())

    sql_alerts = f"""
        SELECT alert_id, rule_id, rule_version, unit_type, unit_key, asset_id, severity,
               score, reason, evidence_refs, window_start, window_end, created_at
        FROM alerts
        WHERE {' AND '.join(alert_clauses)}
        ORDER BY window_start ASC, created_at ASC
        LIMIT ?
    """
    alert_params.append(bounded_limit)
    cursor.execute(sql_alerts, alert_params)
    alert_rows = cursor.fetchall()

    filtered_alerts: list[dict[str, Any]] = []
    for a in alert_rows:
        ad = dict(a)
        refs = []
        if isinstance(ad.get("evidence_refs"), str) and ad["evidence_refs"].strip():
            try:
                refs = json.loads(ad["evidence_refs"])
            except Exception:
                refs = []
        ad["evidence_refs"] = refs

        alert_ts = _parse_timestamp(ad.get("window_start"))
        alert_block = None
        for r in refs:
            if isinstance(r, dict):
                if "block_timestamp" in r and r["block_timestamp"]:
                    alert_ts = int(r["block_timestamp"])
                if "block_number" in r and r["block_number"]:
                    alert_block = int(r["block_number"])
                if "amount_raw" in r and r["amount_raw"] is not None:
                    r["amount_raw"] = str(r["amount_raw"])

        if block_min is not None and alert_block is not None and alert_block < block_min:
            continue
        if block_max is not None and alert_block is not None and alert_block > block_max:
            continue
        if ts_start is not None and alert_ts is not None and alert_ts < ts_start:
            continue
        if ts_end is not None and alert_ts is not None and alert_ts > ts_end:
            continue

        ad["_computed_ts"] = alert_ts
        ad["_computed_block"] = alert_block
        filtered_alerts.append(ad)

    # 4. Assemble and order chronological timeline
    timeline: list[dict[str, Any]] = []

    for b in block_rows:
        timeline.append({
            "event_type": "block",
            "timestamp": b["block_timestamp"],
            "timestamp_utc": b["block_time_utc"],
            "block_number": b["number"],
            "details": {
                "block_hash": b["hash"],
                "status": b["status"],
            },
        })

    for t in transfer_rows:
        amt_raw = str(t["amount_raw"]) if t["amount_raw"] is not None else "0"
        timeline.append({
            "event_type": "transfer",
            "timestamp": t["block_timestamp"],
            "timestamp_utc": t["block_time_utc"],
            "block_number": t["block_number"],
            "details": {
                "tx_hash": t["tx_hash"],
                "log_index": t["log_index"],
                "from_addr": t["from_addr"],
                "to_addr": t["to_addr"],
                "asset_id": t["asset_id"],
                "amount_raw": amt_raw,
            },
        })

    for a in filtered_alerts:
        timeline.append({
            "event_type": "alert",
            "timestamp": a["_computed_ts"],
            "timestamp_utc": a["window_start"],
            "block_number": a["_computed_block"],
            "details": {
                "alert_id": a["alert_id"],
                "rule_id": a["rule_id"],
                "severity": a["severity"],
                "score": a["score"],
                "reason": a["reason"],
                "evidence_refs": a["evidence_refs"],
            },
        })

    type_priority = {"block": 0, "transfer": 1, "alert": 2}
    timeline.sort(
        key=lambda ev: (
            ev["timestamp"] or 0,
            ev["block_number"] or 0,
            type_priority.get(ev["event_type"], 99),
        )
    )

    return timeline[:bounded_limit]


# ==============================================================================
# Authorized Tool 6: collect_missing_range (Staging Only)
# ==============================================================================


def collect_missing_range(
    start_block: int,
    end_block: int,
    staging_db: sqlite3.Connection,
    tracker: ToolCallBudgetTracker | None = None,
    block_fetcher: Callable[[int], dict] | None = None,
    analysis_id: str | None = None,
) -> dict[str, Any]:
    """Collects blockchain data for a missing range into an isolated staging database.

    Guarantees:
    - Enforces <= 20 blocks inclusive; raises RangeLimitExceeded (subclass of ValueError) on 21+.
    - Rejects invalid/inverted/negative ranges with ValueError.
    - Rejects non-integer types with TypeError.
    - Enforces at most 2 calls per session with SessionLimitExceeded.
    - Verifies staging_db is isolated and non-canonical.
    - Creates collector_runs record (mode='ai_tool') and audit_events record ('AI_COLLECT_RANGE').
    - Strict G5-02 invariant: zero replace or ignore SQL statements.
    """
    t0 = time.time()
    count = validate_block_range(start_block, end_block)

    verify_staging_database(staging_db)
    init_staging_tables(staging_db)

    if tracker is not None:
        if tracker.collect_calls >= tracker.max_collect_calls:
            raise SessionLimitExceeded(
                f"Session call limit exceeded: collect_missing_range can be called at most "
                f"{tracker.max_collect_calls} times per session (attempted call #{tracker.collect_calls + 1})"
            )

    run_id = f"ai-run-{uuid.uuid4().hex[:12]}"
    chain_id = 1
    blocks_collected = 0
    txs_collected = 0
    transfers_collected = 0

    with staging_db:
        for b_num in range(start_block, end_block + 1):
            if block_fetcher is not None:
                blk = block_fetcher(b_num)
            else:
                blk = {
                    "number": b_num,
                    "hash": f"0x{'%04x' % b_num}{'00' * 30}",
                    "parentHash": f"0x{'%04x' % (b_num - 1)}{'00' * 30}",
                    "timestamp": 1790812800 + b_num * 12,
                    "transactions": [],
                }

            b_hash = blk.get("hash", f"0x{'%04x' % b_num}{'00' * 30}")
            b_ts = blk.get("timestamp", 1790812800 + b_num * 12)
            now_str = datetime.now(timezone.utc).isoformat()

            existing = staging_db.execute(
                "SELECT 1 FROM blocks WHERE chain_id = ? AND hash = ?",
                (chain_id, b_hash),
            ).fetchone()

            if not existing:
                staging_db.execute(
                    "INSERT INTO blocks(chain_id, number, hash, parent_hash, block_timestamp, "
                    "block_time_utc, first_observed_at, collected_at, status, raw_json, raw_sha256, synthetic) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'staging', ?, 'sha_dummy', 1)",
                    (chain_id, b_num, b_hash, blk.get("parentHash", ""), b_ts, now_str, now_str, now_str, json.dumps(blk)),
                )
            blocks_collected += 1

        dur = max(time.time() - t0, 0.001)
        staging_db.execute(
            "INSERT INTO collector_runs VALUES (?, 'ai_staging_collector', ?, 1, 'ai_tool', "
            "?, ?, ?, ?, ?, ?, 0, 0, NULL, 'success', ?, ?, 'p5_ai_stage')",
            (run_id, chain_id, start_block, end_block, blocks_collected, txs_collected,
             round(blocks_collected / dur, 2), round(txs_collected / dur, 2),
             datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )

        audit_meta = json.dumps({
            "analysis_id": analysis_id,
            "start_block": start_block,
            "end_block": end_block,
            "blocks_count": blocks_collected,
            "run_id": run_id,
            "session_invocation": (tracker.collect_calls + 1) if tracker else 1,
        }, sort_keys=True)
        staging_db.execute(
            "INSERT INTO audit_events(ts, action, object_ref, metadata) VALUES (?, 'AI_COLLECT_RANGE', ?, ?)",
            (datetime.now(timezone.utc).isoformat(), f"range:{start_block}-{end_block}", audit_meta),
        )

    if tracker is not None:
        tracker.collect_calls += 1

    return {
        "status": "success",
        "start_block": start_block,
        "end_block": end_block,
        "blocks_count": blocks_collected,
        "transactions_count": txs_collected,
        "transfers_count": transfers_collected,
        "run_id": run_id,
        "session_collect_call_count": tracker.collect_calls if tracker else 1,
    }


# ==============================================================================
# Authorized Tool: get_threat_intel (Offline Benchmark Threat Intelligence)
# ==============================================================================


def get_threat_intel(
    arg1: Union[sqlite3.Connection, str],
    arg2: Optional[Union[sqlite3.Connection, str]] = None,
    *,
    db: Optional[sqlite3.Connection] = None,
    db_path: Optional[Union[str, Path]] = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Query offline threat intelligence records for a specified address from benchmark_p6.db.

    Guarantees:
    - Strictly read-only query mode (PRAGMA query_only = ON, mode=ro&immutable=1, authorizer).
    - Open World Assumption: Non-matching addresses return an empty list [], NOT marked as benign.
    - Field Separation: Results are external threat intelligence claims intended for
      `external_labels` or `metadata`, and MUST NEVER be classified as `observed_facts`.
    - Sanitized hex address normalization (case-insensitive lowercase matching).

    Args:
        arg1: Target address string, or sqlite3.Connection if passing connection first.
        arg2: Target address string if connection passed first, or optional connection.
        db: Strictly read-only connection to benchmark_p6.db.
        db_path: Optional custom path to benchmark database.
        limit: Max number of matching records to return (default: 100, clamped 1..1000).

    Returns:
        List of matching threat intelligence record dictionaries.
    """
    conn: Optional[sqlite3.Connection] = None
    target_address: str = ""

    if isinstance(arg1, sqlite3.Connection):
        conn = arg1
        if isinstance(arg2, str):
            target_address = arg2
    elif isinstance(arg1, str):
        target_address = arg1
        if isinstance(arg2, sqlite3.Connection):
            conn = arg2

    if conn is None and db is not None:
        conn = db

    if not target_address or not isinstance(target_address, str):
        return []

    norm_addr = target_address.strip().lower()
    if not (norm_addr.startswith("0x") and len(norm_addr) == 42):
        return []

    bounded_limit = max(1, min(int(limit), 1000))
    close_conn = False

    if conn is None:
        target_path = Path(db_path) if db_path is not None else DEFAULT_BENCHMARK_DB_PATH
        if not target_path.exists():
            logger.warning("Benchmark threat intel database not found at: %s", target_path)
            return []
        conn = get_readonly_connection(target_path)
        close_conn = True

    try:
        cursor = conn.cursor()
        query = """
            SELECT entity_value, entity_type, threat_category, threat_sub_tactic,
                   confidence_score, data_source, source_file_path, source_file_sha256,
                   row_identifier, raw_metadata_json, ingestion_timestamp
            FROM threat_intel_records
            WHERE LOWER(entity_value) = ? AND entity_type IN ('address', 'contract')
            ORDER BY ingestion_timestamp DESC
            LIMIT ?
        """
        cursor.execute(query, (norm_addr, bounded_limit))
        rows = cursor.fetchall()

        results: list[dict[str, Any]] = []
        for r in rows:
            val = r[0]
            ent_type = r[1]
            cat = r[2]
            sub = r[3]
            conf = float(r[4]) if r[4] is not None else 1.0
            src = r[5]
            src_path = r[6]
            src_sha = r[7]
            row_id = r[8]
            raw_meta = r[9]
            ing_ts = r[10]

            parsed_meta: Any = None
            if isinstance(raw_meta, str) and raw_meta.strip():
                try:
                    parsed_meta = json.loads(raw_meta)
                except Exception:
                    parsed_meta = raw_meta

            record = {
                "address": val,
                "entity_type": ent_type,
                "threat_category": cat,
                "threat_sub_tactic": sub,
                "confidence_score": conf,
                "data_source": src,
                "source_file_path": src_path,
                "source_file_sha256": src_sha,
                "row_identifier": row_id,
                "raw_metadata": parsed_meta,
                "ingestion_timestamp": ing_ts,
                "external_label": {
                    "source": src,
                    "address_or_tx": val,
                    "category": cat.lower() if cat else "unknown",
                    "entity_name": sub or f"label_{src}",
                    "source_url": src_path,
                    "is_verified": False,
                    "notes": (
                        f"Offline threat intelligence from {src} (file_sha256: {src_sha[:16]}..., "
                        f"confidence: {conf}, row: {row_id})"
                    ),
                },
            }
            results.append(record)

        return results
    finally:
        if close_conn and conn is not None:
            conn.close()


# ==============================================================================
# Security Guardrails & Dispatch Wrapper
# ==============================================================================


def execute_guarded_tool(
    tool_name: str,
    args: dict[str, Any],
    tool_funcs: dict[str, Callable],
    tracker: ToolCallBudgetTracker,
) -> Any:
    """Dispatches tool execution through security guardrails.

    Enforces:
    - Tool authorization check against AUTHORIZED_TOOLS / P6_AUTHORIZED_TOOLS
    - Step budget ceiling (MAX_AI_TOOL_STEPS = 5)
    - Records attempted calls separately from successful calls
    - Structured audit logging for analysis_runs.tool_calls_log
    """
    t0 = time.time()
    step_num = tracker.record_attempt(tool_name, args)

    if tool_name not in AUTHORIZED_TOOLS and tool_name not in P6_AUTHORIZED_TOOLS:
        err = UnauthorizedToolError(
            f"Tool '{tool_name}' is not authorized. Authorized tools are: "
            f"{', '.join(sorted(AUTHORIZED_TOOLS))}"
        )
        tracker.record_failure(
            step_num,
            tool_name,
            args,
            err,
            status="unauthorized",
            duration_ms=(time.time() - t0) * 1000,
        )
        raise err

    func = tool_funcs.get(tool_name)
    if func is None:
        err = NotImplementedError(f"Tool implementation for '{tool_name}' not registered")
        tracker.record_failure(
            step_num,
            tool_name,
            args,
            err,
            status="not_implemented",
            duration_ms=(time.time() - t0) * 1000,
        )
        raise err

    try:
        result = func(**args)
        duration_ms = (time.time() - t0) * 1000
        summary = result if isinstance(result, (int, str, bool, float)) else {
            "type": type(result).__name__,
            "keys": list(result.keys()) if isinstance(result, dict) else None,
            "count": len(result) if isinstance(result, (list, dict)) else None,
        }
        tracker.record_success(step_num, tool_name, args, summary, duration_ms)
        return result
    except Exception as e:
        duration_ms = (time.time() - t0) * 1000
        tracker.record_failure(step_num, tool_name, args, e, status="error", duration_ms=duration_ms)
        raise


execute_tool_with_guardrails = execute_guarded_tool
