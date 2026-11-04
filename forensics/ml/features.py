"""10-Feature extraction pipeline for Ethereum & ERC-20 transactions (P8).

Extracts normalized temporal and volumetric features from canonical database (real_p4.db)
with arbitrary precision arithmetic, robust zero-division safeguards, and pure-Python
matrix operations.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
import sqlite3
from typing import Any, Sequence

try:
    import numpy as np  # type: ignore
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

FEATURE_NAMES: list[str] = [
    "tx_velocity",
    "unique_counterparties_in",
    "unique_counterparties_out",
    "volume_in_normalized",
    "volume_out_normalized",
    "pass_through_ratio",
    "token_diversity",
    "turnover_latency_min",
    "burstiness_std",
    "max_single_out_ratio",
]


def safe_log10(val: int | float) -> float:
    """Computes log10(val + 1.0) with arbitrary precision int overflow safety."""
    if val <= 0:
        return 0.0
    if isinstance(val, int) and val > 10**300:
        s = str(val)
        prefix = float(s[:15])
        exponent = len(s) - 15
        return float(math.log10(prefix) + exponent)
    try:
        return float(math.log10(float(val) + 1.0))
    except (OverflowError, ValueError):
        s = str(int(val))
        return float(math.log10(float(s[:15])) + (len(s) - 15))


class FeatureExtractionResult(tuple):
    """3-tuple (features, addresses, feature_names) with metadata attributes."""
    def __new__(cls, features: Any, addresses: list[str], feature_names: list[str],
                blocks: list[int] | None = None, labels: list[int] | None = None):
        instance = super().__new__(cls, (features, addresses, feature_names))
        instance.features = features
        instance.addresses = addresses
        instance.feature_names = feature_names
        instance.blocks = blocks or []
        instance.labels = labels or []
        return instance


def compute_features_for_transfers(
    target_address: str,
    transfers: Sequence[dict[str, Any]],
) -> list[float]:
    """Computes the 10 canonical features for a set of transfers involving target_address."""
    addr = target_address.strip().lower()
    
    in_transfers: list[dict[str, Any]] = []
    out_transfers: list[dict[str, Any]] = []
    all_blocks: list[int] = []
    asset_ids: set[str] = set()

    for t in transfers:
        f_addr = str(t.get("from_addr", "")).strip().lower()
        t_addr = str(t.get("to_addr", "")).strip().lower()
        b_num = int(t.get("block_number", 0))
        asset_id = str(t.get("asset_id", "")).strip().lower()

        if f_addr == addr or t_addr == addr:
            all_blocks.append(b_num)
            if asset_id:
                asset_ids.add(asset_id)
            if t_addr == addr and f_addr != addr:
                in_transfers.append(t)
            if f_addr == addr and t_addr != addr:
                out_transfers.append(t)

    # 1. tx_velocity
    tx_velocity = float(len(all_blocks))
    if tx_velocity == 0.0:
        return [0.0] * 10

    # 2. unique_counterparties_in
    in_senders = {str(t.get("from_addr", "")).strip().lower() for t in in_transfers}
    unique_counterparties_in = float(len(in_senders))

    # 3. unique_counterparties_out
    out_recipients = {str(t.get("to_addr", "")).strip().lower() for t in out_transfers}
    unique_counterparties_out = float(len(out_recipients))

    # 4 & 5. volume_in_normalized & volume_out_normalized
    v_in_raw = 0
    for t in in_transfers:
        try:
            v_in_raw += int(t.get("amount_raw", 0))
        except (ValueError, TypeError):
            pass

    v_out_raw = 0
    max_out_raw = 0
    for t in out_transfers:
        try:
            amt = int(t.get("amount_raw", 0))
            v_out_raw += amt
            if amt > max_out_raw:
                max_out_raw = amt
        except (ValueError, TypeError):
            pass

    volume_in_normalized = safe_log10(v_in_raw)
    volume_out_normalized = safe_log10(v_out_raw)

    # 6. pass_through_ratio
    if v_out_raw == 0:
        pass_through_ratio = 0.0
    elif v_in_raw == 0:
        pass_through_ratio = 10.0
    else:
        ratio = float(v_out_raw) / float(v_in_raw + 1)
        pass_through_ratio = min(ratio, 10.0)

    # 7. token_diversity
    token_diversity = float(max(len(asset_ids), 1))

    # 8. turnover_latency_min
    min_latency = 999999.0
    has_latency = False
    for t_in in in_transfers:
        b_in = int(t_in.get("block_number", 0))
        for t_out in out_transfers:
            b_out = int(t_out.get("block_number", 0))
            if b_out >= b_in:
                delta = float(b_out - b_in)
                if delta < min_latency:
                    min_latency = delta
                    has_latency = True
    turnover_latency_min = min_latency if has_latency else 0.0

    # 9. burstiness_std
    if len(all_blocks) < 2:
        burstiness_std = 0.0
    else:
        sorted_blocks = sorted(all_blocks)
        deltas = [float(sorted_blocks[i+1] - sorted_blocks[i]) for i in range(len(sorted_blocks)-1)]
        mean_delta = sum(deltas) / len(deltas)
        variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
        burstiness_std = float(math.sqrt(variance))

    # 10. max_single_out_ratio
    if v_out_raw > 0:
        max_single_out_ratio = min(max(float(max_out_raw) / float(v_out_raw), 0.0), 1.0)
    else:
        max_single_out_ratio = 0.0

    return [
        tx_velocity,
        unique_counterparties_in,
        unique_counterparties_out,
        volume_in_normalized,
        volume_out_normalized,
        pass_through_ratio,
        token_diversity,
        turnover_latency_min,
        burstiness_std,
        max_single_out_ratio,
    ]


def extract_address_features(
    db_path_or_conn: Path | str | sqlite3.Connection,
    window_blocks: int = 100,
    min_transfers_per_window: int = 1,
) -> FeatureExtractionResult:
    """Extracts (N, 10) feature matrix, addresses, and feature names from real_p4.db.

    Returns:
        FeatureExtractionResult tuple: (X, addresses, FEATURE_NAMES) with .blocks and .labels.
    """
    owns_conn = False
    if isinstance(db_path_or_conn, sqlite3.Connection):
        conn = db_path_or_conn
    else:
        conn = sqlite3.connect(str(db_path_or_conn))
        conn.row_factory = sqlite3.Row
        owns_conn = True

    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT block_number, from_addr, to_addr, asset_id, amount_raw "
            "FROM asset_transfers ORDER BY block_number ASC"
        )
        rows = cursor.fetchall()

        if not rows:
            empty_arr = np.empty((0, 10), dtype=float) if HAS_NUMPY else []
            return FeatureExtractionResult(empty_arr, [], list(FEATURE_NAMES), [], [])

        # Fetch alert ground truth
        cursor.execute("SELECT unit_key, evidence_refs, window_start, window_end FROM alerts")
        alert_rows = cursor.fetchall()
        alerted_entities: set[str] = set()
        for ar in alert_rows:
            uk = str(ar[0] or "").strip().lower()
            if uk.startswith("0x") and len(uk) == 42:
                alerted_entities.add(uk)
            refs_str = str(ar[1] or "")
            try:
                refs = json.loads(refs_str)
                for r in refs:
                    if isinstance(r, dict):
                        fa = str(r.get("from_addr", "")).strip().lower()
                        ta = str(r.get("to_addr", "")).strip().lower()
                        if fa.startswith("0x") and len(fa) == 42:
                            alerted_entities.add(fa)
                        if ta.startswith("0x") and len(ta) == 42:
                            alerted_entities.add(ta)
            except Exception:
                pass

        # Group transfers by window and entity
        # Window indexing: window_id = block_number // window_blocks
        windows: dict[int, dict[str, list[dict[str, Any]]]] = {}
        for r in rows:
            b_num = int(r["block_number"])
            w_id = b_num // window_blocks
            if w_id not in windows:
                windows[w_id] = {}
            
            f_addr = str(r["from_addr"] or "").strip().lower()
            t_addr = str(r["to_addr"] or "").strip().lower()
            t_dict = {
                "block_number": b_num,
                "from_addr": f_addr,
                "to_addr": t_addr,
                "asset_id": str(r["asset_id"] or ""),
                "amount_raw": str(r["amount_raw"] or "0"),
            }

            if f_addr.startswith("0x") and len(f_addr) == 42:
                if f_addr not in windows[w_id]:
                    windows[w_id][f_addr] = []
                windows[w_id][f_addr].append(t_dict)

            if t_addr.startswith("0x") and len(t_addr) == 42:
                if t_addr not in windows[w_id]:
                    windows[w_id][t_addr] = []
                windows[w_id][t_addr].append(t_dict)

        matrix: list[list[float]] = []
        addresses: list[str] = []
        blocks: list[int] = []
        labels: list[int] = []

        sorted_w_ids = sorted(windows.keys())
        for w_id in sorted_w_ids:
            window_start_block = w_id * window_blocks
            entity_dict = windows[w_id]
            for entity_addr, transfers in entity_dict.items():
                if len(transfers) < min_transfers_per_window:
                    continue
                vec = compute_features_for_transfers(entity_addr, transfers)
                matrix.append(vec)
                addresses.append(entity_addr)
                blocks.append(window_start_block)
                label = 1 if entity_addr in alerted_entities else 0
                labels.append(label)

        if HAS_NUMPY:
            features_out = np.array(matrix, dtype=float)
        else:
            features_out = matrix

        return FeatureExtractionResult(features_out, addresses, list(FEATURE_NAMES), blocks, labels)

    finally:
        if owns_conn:
            conn.close()


def extract_single_address_features(
    db: sqlite3.Connection | str | Path | None,
    address: str,
    window_blocks: int = 100,
    target_block: int | None = None,
) -> dict[str, float]:
    """Extracts the 10 canonical features for a single entity address as a dictionary."""
    norm_addr = address.strip().lower()
    if not (norm_addr.startswith("0x") and len(norm_addr) == 42):
        return {name: 0.0 for name in FEATURE_NAMES}

    if db is None:
        return {name: 0.0 for name in FEATURE_NAMES}

    owns_conn = False
    if isinstance(db, sqlite3.Connection):
        conn = db
    else:
        conn = sqlite3.connect(str(db))
        conn.row_factory = sqlite3.Row
        owns_conn = True

    try:
        cursor = conn.cursor()
        if target_block is not None:
            w_start = (target_block // window_blocks) * window_blocks
            w_end = w_start + window_blocks
            query = (
                "SELECT block_number, from_addr, to_addr, asset_id, amount_raw "
                "FROM asset_transfers WHERE (from_addr = ? OR to_addr = ?) "
                "AND block_number >= ? AND block_number < ? ORDER BY block_number ASC"
            )
            cursor.execute(query, (norm_addr, norm_addr, w_start, w_end))
        else:
            query = (
                "SELECT block_number, from_addr, to_addr, asset_id, amount_raw "
                "FROM asset_transfers WHERE (from_addr = ? OR to_addr = ?) "
                "ORDER BY block_number ASC"
            )
            cursor.execute(query, (norm_addr, norm_addr))

        rows = cursor.fetchall()
        transfers = [
            {
                "block_number": int(r[0]),
                "from_addr": str(r[1] or "").strip().lower(),
                "to_addr": str(r[2] or "").strip().lower(),
                "asset_id": str(r[3] or ""),
                "amount_raw": str(r[4] or "0"),
            }
            for r in rows
        ]
        vec = compute_features_for_transfers(norm_addr, transfers)
        return {name: val for name, val in zip(FEATURE_NAMES, vec)}

    finally:
        if owns_conn:
            conn.close()
