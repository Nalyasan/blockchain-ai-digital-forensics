"""Synthetic P4 fixtures. All callers supply an isolated temporary database."""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone

from forensics.schemas import init_db

ETH = 10**18
TOKEN = "0x" + "a" * 40
TOKEN2 = "0x" + "b" * 40
ZERO = "0x" + "0" * 40
TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def addr(n):
    return "0x" + format(n, "040x")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class Dataset:
    def __init__(self, path):
        self.path = path
        self.conn = init_db(path)
        self.serial = 0

    def close(self):
        self.conn.close()

    def add(self, amount=1, *, asset="NATIVE", sender=None, recipient=None,
            block=100, timestamp=None, chain=1, synthetic=True, status="canonical",
            receipt_status=1, tx=None, log_index=None, tx_index=None, block_hash=None):
        self.serial += 1
        sender = sender if sender is not None else addr(1)
        recipient = recipient if recipient is not None else addr(2)
        timestamp = timestamp if timestamp is not None else 1700000000 + block * 12
        bh = block_hash or "0x" + digest([chain, block])
        th = tx or "0x" + digest([chain, self.serial, block])
        li = (-1 if asset == "NATIVE" else self.serial) if log_index is None else log_index
        ti = self.serial if tx_index is None else tx_index
        utc = datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")
        raw_block = {"number": hex(block), "hash": bh, "timestamp": hex(timestamp)}
        raw_tx = {"hash": th, "blockHash": bh, "blockNumber": hex(block),
                  "transactionIndex": hex(ti), "from": sender, "to": recipient,
                  "value": hex(int(amount)) if asset == "NATIVE" else "0x0", "input": "0x"}
        raw_rc = {"transactionHash": th, "blockHash": bh, "status": hex(receipt_status)}
        self.conn.execute("INSERT OR IGNORE INTO blocks VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                          (chain, block, bh, "0x" + digest([chain, block - 1]), timestamp,
                           utc, utc, utc, status, json.dumps(raw_block, sort_keys=True), digest(raw_block), int(synthetic)))
        self.conn.execute("INSERT OR IGNORE INTO transactions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                          (chain, th, bh, block, ti, sender, recipient, str(amount) if asset == "NATIVE" else "0",
                           0, "0x", json.dumps(raw_tx, sort_keys=True), digest(raw_tx)))
        self.conn.execute("INSERT OR IGNORE INTO receipts VALUES(?,?,?,?,?,?,?,?)",
                          (chain, th, bh, receipt_status, 21000, None, json.dumps(raw_rc, sort_keys=True), digest(raw_rc)))
        if asset != "NATIVE":
            topics = [TOPIC, "0x" + sender[2:].zfill(64), "0x" + recipient[2:].zfill(64)]
            data = "0x" + format(int(amount), "064x")
            raw_log = {"transactionHash": th, "blockHash": bh, "logIndex": hex(li),
                       "address": asset, "topics": topics, "data": data}
            self.conn.execute("INSERT OR IGNORE INTO logs VALUES(?,?,?,?,?,?,?,?)",
                              (chain, bh, li, th, asset, json.dumps(topics), data, json.dumps(raw_log, sort_keys=True)))
        row = dict(chain_id=chain, block_number=block, block_hash=bh, block_timestamp=timestamp,
                   tx_hash=th, log_index=li, asset_id=asset, from_addr=sender, to_addr=recipient,
                   amount_raw=str(amount), synthetic=int(synthetic))
        self.conn.execute("INSERT OR IGNORE INTO asset_transfers(" + ",".join(row) + ") VALUES(" + ",".join("?" for _ in row) + ")", tuple(row.values()))
        self.conn.commit()
        return row


def verify_refs(path, alerts):
    """Independently resolve every full transfer identity and compare source facts."""
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        for alert in alerts:
            assert alert["synthetic"] is True or alert["synthetic"] == 1
            assert alert["evidence_refs"]
            for ref in alert["evidence_refs"]:
                identity = tuple(ref[k] for k in ("chain_id", "block_hash", "tx_hash", "log_index"))
                row = conn.execute("SELECT * FROM asset_transfers WHERE chain_id=? AND block_hash=? AND tx_hash=? AND log_index=?", identity).fetchone()
                assert row is not None, ref
                assert row["asset_id"] == alert["asset_id"]
                for key in ("asset_id", "amount_raw", "from_addr", "to_addr", "block_number"):
                    if key in ref:
                        assert ref[key] == row[key], (key, ref, dict(row))
                assert conn.execute("SELECT 1 FROM transactions WHERE chain_id=? AND block_hash=? AND tx_hash=?", identity[:3]).fetchone()
                assert conn.execute("SELECT 1 FROM blocks WHERE chain_id=? AND hash=? AND status='canonical'", identity[:2]).fetchone()


def source_snapshot(conn):
    return {name: conn.execute("SELECT * FROM " + name + " ORDER BY rowid").fetchall()
            for name in ("blocks", "transactions", "receipts", "logs", "asset_transfers", "custody_events")}
