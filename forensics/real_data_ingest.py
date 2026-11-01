"""Real dataset ingestion and normalization engine for Phase 4 Forensics.

Ingests verified Ethereum Mainnet incident datasets (Euler DAI and Curve alETH),
including canonical window transfers, incident transfers, top-level ETH transfers,
and normalized internal ETH transfers into an isolated P4 SQLite database.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import glob
import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any

from forensics.schemas import init_db
from forensics.persistence import EvidenceConflictError, insert_verified

log = logging.getLogger("forensics.real_data_ingest")

DEFAULT_RESEARCH_DIR = Path("D:/Projest/P4_Research")
DEFAULT_DB_PATH = Path("D:/Projest/worktrees/p4_real_integration/data/real_p4.db")

# Official non-overlapping window boundaries
EULER_DAI_CALIBRATION_BOUNDS = (16816000, 16817989)
EULER_DAI_TEST_BOUNDS = (16817990, 16818110)
CURVE_ALETH_CALIBRATION_BOUNDS = (17700000, 17806699)
CURVE_ALETH_TEST_BOUNDS = (17806700, 17806830)


def parse_timestamp_to_unix(ts_val: str | int | float) -> int:
    """Safely convert ISO UTC string or integer timestamp to integer Unix seconds."""
    if isinstance(ts_val, (int, float)):
        return int(ts_val)
    ts_str = str(ts_val).strip()
    if ts_str.isdigit():
        return int(ts_str)
    # Parse ISO-8601 UTC string
    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    return int(dt.timestamp())


def format_timestamp_utc(unix_ts: int) -> str:
    """Format Unix timestamp integer to ISO-8601 UTC string."""
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()


def find_internal_transfers_file(output_dir: Path) -> Path:
    """Locate output/internal_transfers_*.csv; pick the latest if multiple exist."""
    candidates = sorted(output_dir.glob("internal_transfers_*.csv"))
    if not candidates:
        raise FileNotFoundError(f"No internal_transfers_*.csv found in {output_dir}")
    return candidates[-1]


def ingest_real_dataset(
    research_dir: Path | str = DEFAULT_RESEARCH_DIR,
    db_path: Path | str = DEFAULT_DB_PATH,
    chain_id: int = 1,
) -> dict[str, Any]:
    """Ingest and normalize real Ethereum incident datasets into target SQLite database.

    Returns:
        dict containing ingestion statistics.
    """
    research_path = Path(research_dir)
    output_dir = research_path / "output"
    verification_dir = output_dir / "verification"

    verified_erc20_csv = verification_dir / "p4_erc20_verified_so_far.csv"
    asset_transfers_csv = output_dir / "asset_transfers.csv"
    transactions_csv = output_dir / "transactions.csv"
    internal_transfers_csv = find_internal_transfers_file(output_dir)

    for req_file in (verified_erc20_csv, asset_transfers_csv, transactions_csv, internal_transfers_csv):
        if not req_file.exists():
            raise FileNotFoundError(f"Required dataset file missing: {req_file}")

    db_file_path = Path(db_path)
    os.makedirs(db_file_path.parent, exist_ok=True)
    conn = init_db(str(db_file_path))

    # Read transactions lookup (tx_hash -> tx_dict)
    tx_map: dict[str, dict[str, str]] = {}
    with open(transactions_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            previous = tx_map.get(row["tx_hash"])
            if previous is not None and previous != row:
                raise EvidenceConflictError("transactions: conflicting duplicate source row")
            tx_map[row["tx_hash"]] = row

    verified_keys: dict[tuple[int, str, int], tuple] = {}
    transfers_to_insert: list[tuple] = []
    blocks_map: dict[tuple[int, str], dict[str, Any]] = {}

    # 1. Ingest 6,858 verified ERC-20 window transfers
    # Euler DAI: calibration (6,042) & test (340)
    # Curve alETH: calibration (246) & test (230)
    verified_erc20_count = 0
    with open(verified_erc20_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            cid = int(r["chain_id"])
            b_num = int(r["block_number"])
            b_hash = r["block_hash"]
            b_ts = parse_timestamp_to_unix(r["timestamp_unix"])
            tx_hash = r["tx_hash"]
            log_idx = int(r["log_index"])
            asset_id = r["asset_id"].strip().lower()
            from_addr = r["from_address"].strip().lower()
            to_addr = r["to_address"].strip().lower()
            amount_raw = str(r["amount_raw"]).strip()

            # Record verified key for deduplication of asset_transfers.csv
            verified_keys[(cid, tx_hash, log_idx)] = (
                cid, b_num, b_hash, b_ts, tx_hash, log_idx,
                asset_id, from_addr, to_addr, amount_raw, 0
            )

            transfers_to_insert.append((
                cid, b_num, b_hash, b_ts, tx_hash, log_idx,
                asset_id, from_addr, to_addr, amount_raw, 0
            ))
            verified_erc20_count += 1

            previous_block = blocks_map.get((cid, b_hash))
            if previous_block and (previous_block["number"], previous_block["block_timestamp"]) != (b_num, b_ts):
                raise EvidenceConflictError("blocks: conflicting source payload")
            if (cid, b_hash) not in blocks_map:
                blocks_map[(cid, b_hash)] = {
                    "chain_id": cid,
                    "number": b_num,
                    "hash": b_hash,
                    "block_timestamp": b_ts,
                }

    # 2. Ingest incident transfers from asset_transfers.csv
    # Deduplicate 11 transfers already present in verified ERC-20 dataset.
    # Ingest remaining 152 incident ERC-20 transfers and 6 top-level ETH transfers.
    incident_erc20_count = 0
    toplevel_eth_count = 0
    with open(asset_transfers_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            cid = int(r["chain_id"])
            tx_hash = r["tx_hash"]
            log_idx = int(r["log_index"])

            b_num = int(r["block_number"])
            b_hash = r["block_hash"]
            b_ts = parse_timestamp_to_unix(r["timestamp_utc"])
            from_addr = r["from_address"].strip().lower()
            to_addr = r["to_address"].strip().lower()
            amount_raw = str(r["amount_raw"]).strip()

            asset_type = r.get("asset_type", "").strip().upper()
            raw_asset_id = r.get("asset_id", "").strip()

            if asset_type == "ETH" or raw_asset_id == "native:eth" or log_idx == -1:
                # Top-level ETH transfer: normalized to NATIVE with log_index = -1
                asset_id = "NATIVE"
                toplevel_eth_count += 1
                assigned_log_index = -1
            else:
                asset_id = raw_asset_id.lower()
                incident_erc20_count += 1
                assigned_log_index = log_idx

            if (cid, tx_hash, log_idx) in verified_keys:
                incoming = (cid, b_num, b_hash, b_ts, tx_hash, assigned_log_index,
                            asset_id, from_addr, to_addr, amount_raw, 0)
                if incoming != verified_keys[(cid, tx_hash, log_idx)]:
                    raise EvidenceConflictError("asset_transfers: conflicting source overlap")
                if asset_id == "NATIVE":
                    toplevel_eth_count -= 1
                else:
                    incident_erc20_count -= 1
                continue

            transfers_to_insert.append((
                cid, b_num, b_hash, b_ts, tx_hash, assigned_log_index,
                asset_id, from_addr, to_addr, amount_raw, 0
            ))

            previous_block = blocks_map.get((cid, b_hash))
            if previous_block and (previous_block["number"], previous_block["block_timestamp"]) != (b_num, b_ts):
                raise EvidenceConflictError("blocks: conflicting source payload")
            if (cid, b_hash) not in blocks_map:
                blocks_map[(cid, b_hash)] = {
                    "chain_id": cid,
                    "number": b_num,
                    "hash": b_hash,
                    "block_timestamp": b_ts,
                }

    # 3. Ingest 16 internal ETH transfers from internal_transfers_*.csv
    # - Normalize asset_id from "native:eth" -> "NATIVE"
    # - Assign distinct negative log_index per transaction (e.g. -100 - i)
    # - Preserve exact decimal integer string in amount_raw (from amount_wei)
    # - Populate block_hash and block_timestamp from transactions lookup
    internal_eth_count = 0
    tx_internal_counters: dict[str, int] = {}
    with open(internal_transfers_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            tx_hash = r["tx_hash"]
            tx_info = tx_map.get(tx_hash)
            if not tx_info:
                raise ValueError(f"Transaction hash {tx_hash} from internal transfers not found in transactions.csv")

            cid = int(r["chain_id"])
            b_num = int(tx_info["block_number"])
            b_hash = tx_info["block_hash"]
            b_ts = parse_timestamp_to_unix(tx_info["timestamp_utc"])
            from_addr = r["from_address"].strip().lower()
            to_addr = r["to_address"].strip().lower()
            amount_raw = str(r["amount_wei"]).strip()

            # Assign per-transaction distinct negative log_index
            internal_idx = tx_internal_counters.get(tx_hash, 0)
            tx_internal_counters[tx_hash] = internal_idx + 1
            assigned_log_index = -100 - internal_idx

            asset_id = "NATIVE"
            internal_eth_count += 1

            transfers_to_insert.append((
                cid, b_num, b_hash, b_ts, tx_hash, assigned_log_index,
                asset_id, from_addr, to_addr, amount_raw, 0
            ))

            previous_block = blocks_map.get((cid, b_hash))
            if previous_block and (previous_block["number"], previous_block["block_timestamp"]) != (b_num, b_ts):
                raise EvidenceConflictError("blocks: conflicting source payload")
            if (cid, b_hash) not in blocks_map:
                blocks_map[(cid, b_hash)] = {
                    "chain_id": cid,
                    "number": b_num,
                    "hash": b_hash,
                    "block_timestamp": b_ts,
                }

    # 4. Insert canonical blocks into blocks table
    now_utc_str = datetime.now(timezone.utc).isoformat()
    blocks_to_insert = []
    for b in blocks_map.values():
        b_time_utc = format_timestamp_utc(b["block_timestamp"])
        blocks_to_insert.append((
            b["chain_id"],
            b["number"],
            b["hash"],
            None,  # parent_hash
            b["block_timestamp"],
            b_time_utc,
            b_time_utc,  # first_observed_at
            now_utc_str,  # collected_at
            "canonical",
            None,  # raw_json
            None,  # raw_sha256
            0,  # synthetic
        ))

    # 5. Populate incident transactions into transactions table
    txs_to_insert = []
    for tx in tx_map.values():
        txs_to_insert.append((
            int(tx["chain_id"]),
            tx["tx_hash"],
            tx["block_hash"],
            int(tx["block_number"]),
            int(tx["transaction_index"]),
            tx["from_address"].strip().lower(),
            tx["to_address"].strip().lower(),
            str(tx["value_wei"]).strip(),
            0,  # nonce
            "0x",  # input
            None,  # raw_json
            None,  # raw_sha256
        ))

    # Serialize canonical identity checks and all writes in one transaction.
    try:
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            for values in blocks_to_insert:
                record = dict(zip(
                    "chain_id number hash parent_hash block_timestamp block_time_utc "
                    "first_observed_at collected_at status raw_json raw_sha256 synthetic".split(), values))
                conflicting = conn.execute(
                    "SELECT 1 FROM blocks WHERE chain_id=? AND number=? AND hash<>? "
                    "AND status='canonical'",
                    (record["chain_id"], record["number"], record["hash"]),
                ).fetchone()
                if conflicting:
                    raise EvidenceConflictError("blocks: conflicting canonical hash at accepted height")
                insert_verified(conn, "blocks", record, ("chain_id", "hash"),
                                replay_metadata=("collected_at",))
            for values in txs_to_insert:
                record = dict(zip(
                    "chain_id tx_hash block_hash block_number tx_index from_addr to_addr "
                    "value_raw nonce input raw_json raw_sha256".split(), values))
                conflict = conn.execute(
                    "SELECT 1 FROM transactions WHERE chain_id=? AND tx_hash=? AND block_hash<>?",
                    (record["chain_id"], record["tx_hash"], record["block_hash"]),
                ).fetchone()
                if conflict:
                    raise EvidenceConflictError("transactions: conflicting accepted block identity")
                insert_verified(conn, "transactions", record, ("chain_id", "tx_hash", "block_hash"))
            for values in transfers_to_insert:
                record = dict(zip(
                    "chain_id block_number block_hash block_timestamp tx_hash log_index "
                    "asset_id from_addr to_addr amount_raw synthetic".split(), values))
                insert_verified(conn, "asset_transfers", record,
                                ("chain_id", "block_hash", "tx_hash", "log_index"))
    except Exception:
        conn.close()
        raise

    # Verify counts
    total_transfers = conn.execute("SELECT count(*) FROM asset_transfers").fetchone()[0]
    canonical_blocks = conn.execute("SELECT count(*) FROM blocks WHERE status = 'canonical'").fetchone()[0]
    internal_eth_in_db = conn.execute(
        "SELECT count(*) FROM asset_transfers WHERE asset_id = 'NATIVE' AND log_index < -1"
    ).fetchone()[0]
    toplevel_eth_in_db = conn.execute(
        "SELECT count(*) FROM asset_transfers WHERE asset_id = 'NATIVE' AND log_index = -1"
    ).fetchone()[0]
    erc20_in_db = conn.execute(
        "SELECT count(*) FROM asset_transfers WHERE asset_id != 'NATIVE'"
    ).fetchone()[0]

    # Join verification: ensure every transfer joins with a canonical block
    joined_transfers = conn.execute(
        """
        SELECT count(*) FROM asset_transfers t
        INNER JOIN blocks b ON t.block_hash = b.hash
        WHERE b.status = 'canonical'
        """
    ).fetchone()[0]

    if total_transfers != 7032:
        raise ValueError(f"Expected 7,032 total transfers, got {total_transfers}")
    if joined_transfers != 7032:
        raise ValueError(f"Expected 7,032 transfers joined to canonical blocks, got {joined_transfers}")
    if internal_eth_in_db != 16:
        raise ValueError(f"Expected 16 internal ETH transfers, got {internal_eth_in_db}")
    if toplevel_eth_in_db != 6:
        raise ValueError(f"Expected 6 top-level ETH transfers, got {toplevel_eth_in_db}")

    stats = {
        "total_transfers": total_transfers,
        "verified_erc20": verified_erc20_count,
        "incident_erc20": incident_erc20_count,
        "toplevel_eth": toplevel_eth_count,
        "internal_eth": internal_eth_count,
        "canonical_blocks": canonical_blocks,
        "joined_canonical_transfers": joined_transfers,
        "db_path": str(db_file_path),
    }

    conn.close()
    log.info("Successfully ingested real dataset: %s", stats)
    return stats


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    stats = ingest_real_dataset()
    print("Ingestion complete:", json.dumps(stats, indent=2))
