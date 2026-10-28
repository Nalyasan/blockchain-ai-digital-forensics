#!/usr/bin/env python3
"""Blockchain Forensics Collector (chỉ dùng thư viện chuẩn Python 3.9+).

Lệnh:
  python collector.py healthcheck
  python collector.py backfill --start-block 0 --end-block 100 [--watch-addresses 0x...]
  python collector.py backfill --from-date 2026-10-01 --to-date 2026-10-28
  python collector.py collect [--watch-addresses 0x...]
  python collector.py verify                                                 # kiểm tra SHA-256 raw cục bộ
  python collector.py verify-rpc --start-block 0 --end-block 10             # so khớp nội dung đầy đủ với RPC
  python collector.py timeline --from-date 2026-10-01 --out timeline.csv
"""
import argparse, csv, hashlib, json, logging, os, sqlite3, sys, time, urllib.error, urllib.request, uuid
from datetime import datetime, timezone

# ---------- .env Loader (Thư viện chuẩn, os.environ thật luôn ưu tiên) ----------
def load_dotenv(path=".env"):
    """Đọc file .env tối giản bằng thư viện chuẩn Python. Không bao giờ in/ghi secrets ra log."""
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v
    except Exception as e:
        logging.getLogger("collector").warning("Không thể đọc .env: %s", e)

load_dotenv()

RPC_URL = os.getenv("RPC_URL", "http://127.0.0.1:8545")
RPC_LABEL = os.getenv("RPC_LABEL", "default")
DB_PATH = os.getenv("DB_PATH", "data/forensics.db")
POLL = float(os.getenv("POLL_INTERVAL", "3"))
CONFIRMATIONS = int(os.getenv("CONFIRMATIONS", "2"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "5"))
TIMEOUT = float(os.getenv("TIMEOUT", "15"))
RATE_LIMIT_RPS = float(os.getenv("RATE_LIMIT_RPS", "10"))
RPC_SYNTHETIC = os.getenv("RPC_SYNTHETIC", "false").lower() in ("true", "1", "yes")
RPC_FORK_BLOCK = int(os.getenv("RPC_FORK_BLOCK")) if os.getenv("RPC_FORK_BLOCK") else None
VERSION = "collector-0.2-p1"
ERC20_TRANSFER_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

log = logging.getLogger("collector")

# Metrics phiên chạy
_stats = {"retries": 0}
_last_rpc_time = 0.0

def now_iso(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
def ts_iso(ts): return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def hx(v): return int(v, 16) if isinstance(v, str) else (v or 0)
def sha(obj): return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
def date_to_ts(s):
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return int((d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp())

def is_synthetic(block_number):
    if RPC_SYNTHETIC:
        return 1
    if RPC_FORK_BLOCK is not None and block_number > RPC_FORK_BLOCK:
        return 1
    return 0

def get_commit_hash():
    """Lấy commit hash git qua thư viện chuẩn mà không phụ thuộc vào git CLI."""
    try:
        cur = os.path.dirname(os.path.abspath(__file__))
        git_dir = os.path.join(cur, ".git")
        if os.path.exists(git_dir):
            head_file = os.path.join(git_dir, "HEAD")
            if os.path.exists(head_file):
                with open(head_file, "r", encoding="utf-8") as f:
                    ref = f.read().strip()
                if ref.startswith("ref: "):
                    ref_path = os.path.join(git_dir, ref[5:].replace("/", os.sep))
                    if os.path.exists(ref_path):
                        with open(ref_path, "r", encoding="utf-8") as f:
                            return f.read().strip()[:40]
                return ref[:40]
    except Exception:
        pass
    return "0000000000000000000000000000000000000000"

def _rate_limit():
    global _last_rpc_time
    if RATE_LIMIT_RPS > 0:
        min_interval = 1.0 / RATE_LIMIT_RPS
        elapsed = time.time() - _last_rpc_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        _last_rpc_time = time.time()

class MethodNotFoundError(Exception):
    """Lỗi JSON-RPC -32601: method không được hỗ trợ bởi node (không retry)."""
    pass

_supports_block_receipts = True

# ---------- RPC (read-only, retry + exponential backoff, rate limit, HTTP 429 Retry-After) ----------
def rpc(method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    for attempt in range(MAX_RETRIES):
        _rate_limit()
        try:
            req = urllib.request.Request(RPC_URL, body, {"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                out = json.loads(r.read())
            if "error" in out:
                err = out["error"]
                code = err.get("code") if isinstance(err, dict) else None
                if code == -32601 or "unsupported" in str(err).lower():
                    raise MethodNotFoundError(err)
                raise RuntimeError(err)
            return out["result"]
        except MethodNotFoundError:
            raise
        except urllib.error.HTTPError as e:
            _stats["retries"] += 1
            retry_after = e.headers.get("Retry-After") if e.headers else None
            if e.code == 429 and retry_after:
                try:
                    wait = float(retry_after)
                except ValueError:
                    wait = min(2 ** attempt, 30)
            else:
                wait = min(2 ** attempt, 30)
            log.warning("RPC %s HTTP %d (%s), thử lại sau %ss [%d/%d]", method, e.code, e, wait, attempt + 1, MAX_RETRIES)
            time.sleep(wait)
        except Exception as e:
            _stats["retries"] += 1
            wait = min(2 ** attempt, 30)
            log.warning("RPC %s lỗi (%s), thử lại sau %ss [%d/%d]", method, e, wait, attempt + 1, MAX_RETRIES)
            time.sleep(wait)
    raise ConnectionError(f"RPC {method} thất bại sau {MAX_RETRIES} lần")

def rpc_batch(calls):
    """Gửi mảng các lệnh JSON-RPC trong 1 HTTP request."""
    if not calls:
        return []
    payload = []
    for i, (m, p) in enumerate(calls):
        payload.append({"jsonrpc": "2.0", "id": i + 1, "method": m, "params": p or []})
    body = json.dumps(payload).encode()
    for attempt in range(MAX_RETRIES):
        _rate_limit()
        try:
            req = urllib.request.Request(RPC_URL, body, {"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                resps = json.loads(r.read())
            if isinstance(resps, dict) and "error" in resps:
                raise RuntimeError(resps["error"])
            # Sắp xếp kết quả theo đúng id yêu cầu
            res_dict = {item["id"]: item.get("result") for item in resps if "id" in item}
            return [res_dict.get(i + 1) for i in range(len(calls))]
        except urllib.error.HTTPError as e:
            _stats["retries"] += 1
            retry_after = e.headers.get("Retry-After") if e.headers else None
            wait = float(retry_after) if (e.code == 429 and retry_after) else min(2 ** attempt, 30)
            log.warning("RPC Batch HTTP %d, thử lại sau %ss [%d/%d]", e.code, wait, attempt + 1, MAX_RETRIES)
            time.sleep(wait)
        except Exception as e:
            _stats["retries"] += 1
            wait = min(2 ** attempt, 30)
            log.warning("RPC Batch lỗi (%s), thử lại sau %ss [%d/%d]", e, wait, attempt + 1, MAX_RETRIES)
            time.sleep(wait)
    raise ConnectionError(f"RPC Batch thất bại sau {MAX_RETRIES} lần")

def get_block(n, full=True):
    return rpc("eth_getBlockByNumber", [hex(n), full])

def get_receipts_for_block(blk):
    """Ưu tiên eth_getBlockReceipts; fallback sang batch eth_getTransactionReceipt; cuối cùng là tuần tự."""
    global _supports_block_receipts
    n_hex = blk["number"]
    txs = blk.get("transactions", [])
    if not txs:
        return {}

    # 1. Thử eth_getBlockReceipts nếu chưa bị đánh dấu không hỗ trợ
    if _supports_block_receipts:
        try:
            res = rpc("eth_getBlockReceipts", [n_hex])
            if res and isinstance(res, list):
                return {r["transactionHash"].lower(): r for r in res if r and "transactionHash" in r}
        except MethodNotFoundError:
            _supports_block_receipts = False
            log.debug("Node không hỗ trợ eth_getBlockReceipts, chuyển sang batch fallback")
        except Exception as e:
            log.debug("eth_getBlockReceipts không khả dụng (%s), chuyển sang JSON-RPC batch", e)

    # 2. Fallback JSON-RPC Batch
    try:
        calls = [("eth_getTransactionReceipt", [tx["hash"]]) for tx in txs]
        batch_res = rpc_batch(calls)
        receipts = {}
        for tx, rc in zip(txs, batch_res):
            if rc is not None:
                receipts[tx["hash"].lower()] = rc
        if len(receipts) == len(txs):
            return receipts
    except Exception as e:
        log.debug("Batch receipts lỗi (%s), chuyển sang tuần tự", e)

    # 3. Fallback tuần tự từng giao dịch
    receipts = {}
    for tx in txs:
        rc = rpc("eth_getTransactionReceipt", [tx["hash"]])
        if rc is None:
            raise RuntimeError(f"receipt chưa sẵn sàng: {tx['hash']}")
        receipts[tx["hash"].lower()] = rc
    return receipts

# ---------- DB & Schema Migration ----------
SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks(
  chain_id INT, number INT, hash TEXT, parent_hash TEXT, block_timestamp INT,
  block_time_utc TEXT, first_observed_at TEXT, collected_at TEXT, status TEXT DEFAULT 'canonical',
  raw_json TEXT, raw_sha256 TEXT, synthetic INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE IF NOT EXISTS checkpoints(
  chain_id INT, stream TEXT, last_block INT, last_hash TEXT, updated_at TEXT,
  PRIMARY KEY(chain_id, stream)
);
CREATE TABLE IF NOT EXISTS audit_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, action TEXT, object_ref TEXT, metadata TEXT
);
CREATE TABLE IF NOT EXISTS asset_transfers(
  transfer_id INTEGER PRIMARY KEY AUTOINCREMENT,
  chain_id INT, block_number INT, block_hash TEXT, block_timestamp INT, tx_hash TEXT, log_index INT,
  asset_id TEXT, from_addr TEXT, to_addr TEXT, amount_raw TEXT, synthetic INTEGER NOT NULL DEFAULT 0,
  UNIQUE(chain_id, block_hash, tx_hash, log_index)
);
CREATE TABLE IF NOT EXISTS collector_runs(
  run_id TEXT PRIMARY KEY, rpc_label TEXT, chain_id INT, synthetic INT, mode TEXT,
  start_block INT, end_block INT, blocks_count INT, txs_count INT,
  blocks_per_sec REAL, txs_per_sec REAL, retries_count INT, gaps_count INT,
  watch_filter TEXT, status TEXT, started_at TEXT, ended_at TEXT, commit_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_blocks_time ON blocks(block_timestamp);
CREATE INDEX IF NOT EXISTS idx_tx_from ON transactions(from_addr);
CREATE INDEX IF NOT EXISTS idx_tx_to ON transactions(to_addr);
CREATE INDEX IF NOT EXISTS idx_transfers_from ON asset_transfers(from_addr);
CREATE INDEX IF NOT EXISTS idx_transfers_to ON asset_transfers(to_addr);
CREATE INDEX IF NOT EXISTS idx_transfers_asset ON asset_transfers(asset_id);
"""

def migrate_db(c):
    """Đảm bảo bảng blocks cũ có cột synthetic qua ALTER TABLE an toàn."""
    cols = [r[1] for r in c.execute("PRAGMA table_info(blocks)").fetchall()]
    if cols and "synthetic" not in cols:
        c.execute("ALTER TABLE blocks ADD COLUMN synthetic INTEGER NOT NULL DEFAULT 0")
        log.info("Đã migrate: thêm cột synthetic vào bảng blocks")

def db(path=None):
    p = path or DB_PATH
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    c = sqlite3.connect(p)
    c.executescript(SCHEMA)
    migrate_db(c)
    return c

def audit(c, action, ref, meta=None):
    c.execute("INSERT INTO audit_events(ts,action,object_ref,metadata) VALUES(?,?,?,?)",
              (now_iso(), action, ref, json.dumps(meta or {}, sort_keys=True)))

def get_cp(c, chain_id):
    r = c.execute("SELECT last_block,last_hash FROM checkpoints WHERE chain_id=? AND stream='main'", (chain_id,)).fetchone()
    return r if r else (None, None)

# ---------- Trích xuất Chuyển giao Tài sản (ETH & ERC-20) ----------
def extract_transfers(chain_id, blk, receipts, synth_flag):
    transfers = []
    b_num = hx(blk["number"])
    b_hash = blk["hash"]
    b_ts = hx(blk["timestamp"])

    for tx in blk.get("transactions", []):
        tx_h = tx["hash"]
        rc = receipts.get(tx_h.lower())
        if not rc:
            continue
        status = hx(rc.get("status"))

        # 1. Chuyển ETH gốc: tx.value > 0 và receipt.status == 1
        val_int = hx(tx.get("value"))
        if val_int > 0 and status == 1:
            from_addr = (tx.get("from") or "").lower()
            to_addr = tx.get("to")
            if to_addr:
                to_addr = to_addr.lower()
            else:
                to_addr = (rc.get("contractAddress") or "").lower()

            transfers.append({
                "chain_id": chain_id,
                "block_number": b_num,
                "block_hash": b_hash,
                "block_timestamp": b_ts,
                "tx_hash": tx_h,
                "log_index": -1,
                "asset_id": "NATIVE",
                "from_addr": from_addr,
                "to_addr": to_addr,
                "amount_raw": str(val_int),
                "synthetic": synth_flag
            })

        # 2. Chuyển ERC-20: status == 1 và logs Transfer với đúng 3 topics
        if status == 1:
            for lg in rc.get("logs", []):
                topics = lg.get("topics", [])
                if len(topics) == 3 and topics[0].lower() == ERC20_TRANSFER_TOPIC0:
                    try:
                        from_hex = "0x" + topics[1][-40:].lower()
                        to_hex = "0x" + topics[2][-40:].lower()
                        raw_data = lg.get("data", "0x0")
                        amt_int = int(raw_data, 16) if raw_data and raw_data != "0x" else 0
                        token_addr = (lg.get("address") or "").lower()
                        log_idx = hx(lg.get("logIndex", 0))

                        transfers.append({
                            "chain_id": chain_id,
                            "block_number": b_num,
                            "block_hash": b_hash,
                            "block_timestamp": b_ts,
                            "tx_hash": tx_h,
                            "log_index": log_idx,
                            "asset_id": token_addr,
                            "from_addr": from_hex,
                            "to_addr": to_hex,
                            "amount_raw": str(amt_int),
                            "synthetic": synth_flag
                        })
                    except Exception as e:
                        log.warning("Không thể giải mã log ERC-20 tx %s index %s: %s", tx_h, lg.get("logIndex"), e)

    return transfers

# ---------- Lưu 1 block (nguyên tử) ----------
def store_block(c, chain_id, blk, observed, watch_addresses=None):
    n, h = hx(blk["number"]), blk["hash"]
    synth_flag = is_synthetic(n)
    receipts = get_receipts_for_block(blk)
    watch_set = set(a.lower() for a in watch_addresses) if watch_addresses else None

    with c:
        # Cập nhật blocks
        c.execute("INSERT INTO blocks(chain_id,number,hash,parent_hash,block_timestamp,block_time_utc,"
                  "first_observed_at,collected_at,status,raw_json,raw_sha256,synthetic) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(chain_id,hash) DO UPDATE SET status='canonical', synthetic=excluded.synthetic",
                  (chain_id, n, h, blk["parentHash"], hx(blk["timestamp"]), ts_iso(hx(blk["timestamp"])),
                   observed, now_iso(), "canonical", json.dumps(blk, sort_keys=True), sha(blk), synth_flag))

        # Lưu transactions (KHÔNG lọc theo watch_addresses để giữ tính toàn vẹn)
        for tx in blk.get("transactions", []):
            tx_h = tx["hash"]
            c.execute("INSERT OR IGNORE INTO transactions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                      (chain_id, tx_h, h, n, hx(tx.get("transactionIndex")), tx.get("from"), tx.get("to"),
                       str(hx(tx.get("value"))), hx(tx.get("nonce")), tx.get("input"), json.dumps(tx, sort_keys=True), sha(tx)))

            rc = receipts.get(tx_h.lower())
            if not rc:
                continue

            # Lọc receipt/logs nếu bật --watch-addresses
            save_receipt_details = True
            if watch_set is not None:
                from_hit = (tx.get("from") or "").lower() in watch_set
                to_hit = (tx.get("to") or "").lower() in watch_set
                log_hit = any((lg.get("address") or "").lower() in watch_set for lg in rc.get("logs", []))
                save_receipt_details = from_hit or to_hit or log_hit

            if save_receipt_details:
                c.execute("INSERT OR IGNORE INTO receipts VALUES(?,?,?,?,?,?,?,?)",
                          (chain_id, tx_h, h, hx(rc.get("status")), hx(rc.get("gasUsed")),
                           rc.get("contractAddress"), json.dumps(rc, sort_keys=True), sha(rc)))
                for lg in rc.get("logs", []):
                    c.execute("INSERT OR IGNORE INTO logs VALUES(?,?,?,?,?,?,?,?)",
                              (chain_id, h, hx(lg.get("logIndex", 0)), tx_h, lg.get("address"),
                               json.dumps(lg.get("topics", [])), lg.get("data"), json.dumps(lg, sort_keys=True)))
            else:
                # Vẫn lưu receipt cơ bản không logs để biết trạng thái
                c.execute("INSERT OR IGNORE INTO receipts VALUES(?,?,?,?,?,?,?,?)",
                          (chain_id, tx_h, h, hx(rc.get("status")), hx(rc.get("gasUsed")),
                           rc.get("contractAddress"), json.dumps({"status": rc.get("status")}, sort_keys=True), sha({"status": rc.get("status")})))

        # Trích xuất và lưu asset_transfers
        transfers = extract_transfers(chain_id, blk, receipts, synth_flag)
        for tf in transfers:
            if watch_set is not None:
                if tf["from_addr"] not in watch_set and tf["to_addr"] not in watch_set and tf["asset_id"] not in watch_set:
                    continue
            c.execute("INSERT OR IGNORE INTO asset_transfers(chain_id,block_number,block_hash,block_timestamp,"
                      "tx_hash,log_index,asset_id,from_addr,to_addr,amount_raw,synthetic) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                      (tf["chain_id"], tf["block_number"], tf["block_hash"], tf["block_timestamp"],
                       tf["tx_hash"], tf["log_index"], tf["asset_id"], tf["from_addr"], tf["to_addr"], tf["amount_raw"], tf["synthetic"]))

        c.execute("INSERT OR REPLACE INTO checkpoints VALUES(?,?,?,?,?)", (chain_id, "main", n, h, now_iso()))

def handle_reorg(c, chain_id, n):
    k = n - 1
    while k >= 0:
        row = c.execute("SELECT hash FROM blocks WHERE chain_id=? AND number=? AND status='canonical'", (chain_id, k)).fetchone()
        if row is None or get_block(k, False)["hash"] == row[0]:
            break
        k -= 1
    with c:
        for num, h in c.execute("SELECT number,hash FROM blocks WHERE chain_id=? AND number>? AND status='canonical'", (chain_id, k)).fetchall():
            c.execute("UPDATE blocks SET status='orphaned' WHERE chain_id=? AND hash=?", (chain_id, h))
            audit(c, "BLOCK_ORPHANED", f"block:{num}", {"hash": h})
        base = c.execute("SELECT hash FROM blocks WHERE chain_id=? AND number=? AND status='canonical'", (chain_id, k)).fetchone()
        c.execute("INSERT OR REPLACE INTO checkpoints VALUES(?,?,?,?,?)", (chain_id, "main", k, base[0] if base else None, now_iso()))
        audit(c, "REORG_DETECTED", f"block:{n}", {"common_ancestor": k})
    log.error("REORG nghi vấn tại block %d, quay lại điểm chung %d", n, k)
    return k

def record_collector_run(c, chain_id, mode, s, e, b_cnt, tx_cnt, t0, t1, retries, status="success", watch_filter=None):
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    dur = max(t1 - t0, 0.001)
    bps = round(b_cnt / dur, 3)
    tps = round(tx_cnt / dur, 3)
    gaps = len(check_gaps(c))
    synth = 1 if (RPC_SYNTHETIC or (RPC_FORK_BLOCK and (e or 0) > RPC_FORK_BLOCK)) else 0
    c.execute(
        "INSERT INTO collector_runs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (run_id, RPC_LABEL, chain_id, synth, mode, s, e, b_cnt, tx_cnt,
         bps, tps, retries, gaps, watch_filter, status, ts_iso(t0), ts_iso(t1), get_commit_hash())
    )
    c.commit()
    log.info("Đã ghi collector_runs id=%s (blocks=%d, txs=%d, %.2f blk/s)", run_id, b_cnt, tx_cnt, bps)

def sync_range(c, chain_id, start, end, watch_addresses=None, mode="backfill"):
    n = start
    t0 = time.time()
    b_cnt = 0
    tx_cnt = 0
    init_retries = _stats["retries"]
    watch_filter_str = ",".join(watch_addresses) if watch_addresses else None

    if watch_addresses:
        audit(c, "WATCH_FILTER_ACTIVE", f"range:{start}-{end}", {"addresses": watch_addresses})
        c.commit()

    try:
        while n <= end:
            blk = get_block(n)
            if blk is None:
                raise RuntimeError(f"block {n} không tồn tại (data gap)")
            prev = c.execute("SELECT hash FROM blocks WHERE chain_id=? AND number=? AND status='canonical'", (chain_id, n - 1)).fetchone()
            same = c.execute("SELECT hash FROM blocks WHERE chain_id=? AND number=? AND status='canonical'", (chain_id, n)).fetchone()
            if (prev and prev[0] != blk["parentHash"]) or (same and same[0] != blk["hash"]):
                n = handle_reorg(c, chain_id, n) + 1
                continue
            store_block(c, chain_id, blk, now_iso(), watch_addresses)
            b_cnt += 1
            tx_cnt += len(blk.get("transactions", []))
            n += 1
        t1 = time.time()
        record_collector_run(c, chain_id, mode, start, end, b_cnt, tx_cnt, t0, t1, _stats["retries"] - init_retries, "success", watch_filter_str)
        log.info("Đã lưu block %d..%d", start, end)
    except Exception as e:
        t1 = time.time()
        record_collector_run(c, chain_id, mode, start, end, b_cnt, tx_cnt, t0, t1, _stats["retries"] - init_retries, f"error: {e}", watch_filter_str)
        raise

def check_gaps(c):
    return c.execute(
        "SELECT a.number+1, MIN(b.number)-1 FROM blocks a JOIN blocks b ON b.number>a.number "
        "WHERE a.status='canonical' AND b.status='canonical' GROUP BY a.number "
        "HAVING MIN(b.number) > a.number+1"
    ).fetchall()

# ---------- Chuyển NGÀY -> BLOCK ----------
def first_block_at_or_after(ts, latest):
    lo, hi = 0, latest
    if hx(get_block(latest, False)["timestamp"]) < ts:
        return latest + 1
    while lo < hi:
        mid = (lo + hi) // 2
        if hx(get_block(mid, False)["timestamp"]) >= ts:
            hi = mid
        else:
            lo = mid + 1
    return lo

def resolve_range(a, latest):
    if a.from_date or a.to_date:
        s = first_block_at_or_after(date_to_ts(a.from_date), latest) if a.from_date else 0
        e = first_block_at_or_after(date_to_ts(a.to_date) + 86400, latest) - 1 if a.to_date else latest
        log.info("Khoảng thời gian -> block %d..%d", s, e)
        return s, e
    return a.start_block, (a.end_block if a.end_block is not None else latest)

# ---------- Commands ----------
def cmd_healthcheck(a):
    print(json.dumps({
        "rpc": RPC_URL,
        "chain_id": hx(rpc("eth_chainId")),
        "latest_block": hx(rpc("eth_blockNumber")),
        "db": DB_PATH,
        "synthetic": RPC_SYNTHETIC
    }))

def cmd_backfill(a):
    c = db()
    chain_id = hx(rpc("eth_chainId"))
    latest = hx(rpc("eth_blockNumber"))
    s, e = resolve_range(a, latest)
    e = min(e, latest)
    watch_addrs = [x.strip() for x in a.watch_addresses.split(",")] if getattr(a, "watch_addresses", None) else None
    audit(c, "BACKFILL_START", f"range:{s}-{e}", {"version": VERSION, "watch": bool(watch_addrs)})
    c.commit()
    sync_range(c, chain_id, s, e, watch_addresses=watch_addrs, mode="backfill")
    audit(c, "BACKFILL_END", f"range:{s}-{e}")
    c.commit()

def cmd_collect(a):
    c = db()
    chain_id = hx(rpc("eth_chainId"))
    watch_addrs = [x.strip() for x in a.watch_addresses.split(",")] if getattr(a, "watch_addresses", None) else None
    audit(c, "COLLECT_START", f"chain:{chain_id}", {"version": VERSION, "confirmations": CONFIRMATIONS, "watch": bool(watch_addrs)})
    c.commit()
    log.info("Collector liên tục chạy (Ctrl+C để dừng)")
    try:
        while True:
            try:
                last, _ = get_cp(c, chain_id)
                start = (last + 1) if last is not None else a.start_block
                safe = hx(rpc("eth_blockNumber")) - CONFIRMATIONS
                if start <= safe:
                    sync_range(c, chain_id, start, safe, watch_addresses=watch_addrs, mode="continuous")
            except Exception as e:
                log.error("Vòng thu thập lỗi: %s", e)
                audit(c, "COLLECT_ERROR", "loop", {"error": str(e)})
                c.commit()
            time.sleep(POLL)
    except KeyboardInterrupt:
        audit(c, "COLLECT_STOP", f"chain:{chain_id}")
        c.commit()

def cmd_verify(a):
    c = db()
    bad = 0
    for tbl in ("blocks", "transactions", "receipts"):
        for rid, raw, h in c.execute(f"SELECT rowid, raw_json, raw_sha256 FROM {tbl}"):
            if sha(json.loads(raw)) != h:
                bad += 1
                print(f"MISMATCH {tbl} rowid={rid}")
    gaps = check_gaps(c)
    for g in gaps:
        print(f"DATA GAP: block {g[0]}..{g[1]}")
    msg = "OK: raw data khớp SHA-256" if not bad else f"{bad} bản ghi bị sửa!"
    print(msg, "| gaps:", len(gaps))
    return 1 if (bad or gaps) else 0

def cmd_verify_rpc(a):
    """Xác minh 3 tầng (Tầng 2 - RPC): so sánh đối chiếu nội dung đầy đủ giữa SQLite và RPC nguồn."""
    c = db()
    chain_id = hx(rpc("eth_chainId"))
    latest = hx(rpc("eth_blockNumber"))
    start = a.start_block if a.start_block is not None else 0
    end = min(a.end_block if a.end_block is not None else latest, latest)
    mismatches = 0
    total_checked = 0

    log.info("Bắt đầu verify-rpc cho khoảng block %d..%d...", start, end)

    for n in range(start, end + 1):
        db_blk_row = c.execute(
            "SELECT hash, parent_hash, raw_json FROM blocks WHERE chain_id=? AND number=? AND status='canonical'",
            (chain_id, n)
        ).fetchone()

        if not db_blk_row:
            print(f"VERIFY-RPC LỖI: Block {n} thiếu trong DB")
            mismatches += 1
            continue

        rpc_blk = get_block(n, full=True)
        if not rpc_blk:
            print(f"VERIFY-RPC LỖI: Block {n} không tồn tại trên RPC")
            mismatches += 1
            continue

        # 1. So khớp header block và raw_json
        if db_blk_row[0].lower() != rpc_blk["hash"].lower():
            print(f"MISMATCH HASH block {n}: DB={db_blk_row[0]} vs RPC={rpc_blk['hash']}")
            mismatches += 1
        if db_blk_row[1].lower() != rpc_blk["parentHash"].lower():
            print(f"MISMATCH PARENT_HASH block {n}: DB={db_blk_row[1]} vs RPC={rpc_blk['parentHash']}")
            mismatches += 1

        db_raw = json.loads(db_blk_row[2])
        if db_raw.get("hash", "").lower() != rpc_blk.get("hash", "").lower():
            print(f"CONTENT_MISMATCH block {n} raw_json hash: DB={db_raw.get('hash')} vs RPC={rpc_blk.get('hash')}")
            mismatches += 1
        if db_raw.get("parentHash", "").lower() != rpc_blk.get("parentHash", "").lower():
            print(f"CONTENT_MISMATCH block {n} raw_json parentHash: DB={db_raw.get('parentHash')} vs RPC={rpc_blk.get('parentHash')}")
            mismatches += 1
        if hx(db_raw.get("timestamp")) != hx(rpc_blk.get("timestamp")):
            print(f"CONTENT_MISMATCH block {n} raw_json timestamp: DB={db_raw.get('timestamp')} vs RPC={rpc_blk.get('timestamp')}")
            mismatches += 1

        # 2. So sánh nội dung chi tiết từng transaction
        rpc_txs = rpc_blk.get("transactions", [])
        rpc_receipts = get_receipts_for_block(rpc_blk)

        for tx in rpc_txs:
            tx_h = tx["hash"]
            db_tx = c.execute(
                "SELECT from_addr, to_addr, value_raw, input FROM transactions WHERE chain_id=? AND tx_hash=?",
                (chain_id, tx_h)
            ).fetchone()

            if not db_tx:
                print(f"CONTENT_MISMATCH block {n}: Tx {tx_h} thiếu trong transactions SQLite")
                mismatches += 1
                continue

            # Đối chiếu value, from, to, input
            rpc_val = str(hx(tx.get("value")))
            if db_tx[2] != rpc_val:
                print(f"CONTENT_MISMATCH block {n} tx {tx_h} value: DB={db_tx[2]} vs RPC={rpc_val}")
                mismatches += 1
            if (db_tx[0] or "").lower() != (tx.get("from") or "").lower():
                print(f"CONTENT_MISMATCH block {n} tx {tx_h} from: DB={db_tx[0]} vs RPC={tx.get('from')}")
                mismatches += 1
            if (db_tx[1] or "").lower() != (tx.get("to") or "").lower():
                print(f"CONTENT_MISMATCH block {n} tx {tx_h} to: DB={db_tx[1]} vs RPC={tx.get('to')}")
                mismatches += 1
            rpc_input = (tx.get("input") or "0x").lower()
            db_input = (db_tx[3] or "0x").lower()
            if db_input != rpc_input:
                print(f"CONTENT_MISMATCH block {n} tx {tx_h} input: DB={db_input} vs RPC={rpc_input}")
                mismatches += 1

            # Đối chiếu receipt status, gasUsed và logs (đầy đủ topics, data)
            rc = rpc_receipts.get(tx_h.lower())
            if rc:
                db_rc = c.execute(
                    "SELECT status, contract_address, gas_used FROM receipts WHERE chain_id=? AND tx_hash=?",
                    (chain_id, tx_h)
                ).fetchone()
                if db_rc and db_rc[0] != hx(rc.get("status")):
                    print(f"CONTENT_MISMATCH block {n} tx {tx_h} receipt status: DB={db_rc[0]} vs RPC={hx(rc.get('status'))}")
                    mismatches += 1
                if db_rc and db_rc[2] != hx(rc.get("gasUsed")):
                    print(f"CONTENT_MISMATCH block {n} tx {tx_h} receipt gasUsed: DB={db_rc[2]} vs RPC={hx(rc.get('gasUsed'))}")
                    mismatches += 1

                for lg in rc.get("logs", []):
                    l_idx = hx(lg.get("logIndex", 0))
                    db_lg = c.execute(
                        "SELECT address, topics, data FROM logs WHERE chain_id=? AND tx_hash=? AND log_index=?",
                        (chain_id, tx_h, l_idx)
                    ).fetchone()
                    if db_lg:
                        if db_lg[0].lower() != (lg.get("address") or "").lower():
                            print(f"CONTENT_MISMATCH block {n} log {l_idx} address: DB={db_lg[0]} vs RPC={lg.get('address')}")
                            mismatches += 1
                        if json.loads(db_lg[1]) != lg.get("topics", []):
                            print(f"CONTENT_MISMATCH block {n} log {l_idx} topics")
                            mismatches += 1
                        rpc_data = (lg.get("data") or "0x").lower()
                        db_data = (db_lg[2] or "0x").lower()
                        if db_data != rpc_data:
                            print(f"CONTENT_MISMATCH block {n} log {l_idx} data: DB={db_data} vs RPC={rpc_data}")
                            mismatches += 1

        total_checked += 1

    if mismatches == 0:
        print(f"OK: verify-rpc hoàn tất, đối chiếu nội dung đầy đủ khớp 100% với RPC nguồn ({total_checked} blocks).")
        return 0
    else:
        print(f"THẤT BẠI: verify-rpc phát hiện {mismatches} sai lệch nội dung giữa SQLite và RPC!")
        return 1

def cmd_verify_derived(a):
    """Tính lại asset_transfers từ dữ liệu thô (transactions, receipts, logs) của các block canonical và đối chiếu với bảng asset_transfers."""
    c = db()
    bad = 0
    blocks = c.execute(
        "SELECT chain_id, number, hash, raw_json, synthetic FROM blocks WHERE status='canonical' ORDER BY number"
    ).fetchall()

    for chain_id, b_num, b_hash, blk_raw_json, synth in blocks:
        blk = json.loads(blk_raw_json)
        receipts = {}
        for r_row in c.execute("SELECT tx_hash, raw_json FROM receipts WHERE chain_id=? AND block_hash=?", (chain_id, b_hash)).fetchall():
            tx_h, r_json = r_row
            receipts[tx_h.lower()] = json.loads(r_json)

        # Tính lại transfers từ dữ liệu thô
        derived = extract_transfers(chain_id, blk, receipts, synth)
        derived_map = {(t["chain_id"], t["block_hash"], t["tx_hash"].lower(), t["log_index"]): t for t in derived}

        # Đọc các transfer đang lưu trong bảng asset_transfers
        stored = c.execute(
            "SELECT chain_id, block_hash, tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic "
            "FROM asset_transfers WHERE chain_id=? AND block_hash=?",
            (chain_id, b_hash)
        ).fetchall()
        stored_map = {(r[0], r[1], r[2].lower(), r[3]): {
            "asset_id": r[4], "from_addr": r[5], "to_addr": r[6], "amount_raw": r[7], "synthetic": r[8]
        } for r in stored}

        if set(derived_map.keys()) != set(stored_map.keys()):
            print(f"DERIVED_MISMATCH block {b_num}: keys không khớp! derived={len(derived_map)} vs stored={len(stored_map)}")
            bad += 1
            continue

        for k, d_tf in derived_map.items():
            s_tf = stored_map[k]
            for field in ("asset_id", "from_addr", "to_addr", "amount_raw", "synthetic"):
                if str(d_tf[field]).lower() != str(s_tf[field]).lower():
                    print(f"DERIVED_MISMATCH block {b_num} tx {k[2]} field {field}: derived={d_tf[field]} vs stored={s_tf[field]}")
                    bad += 1

    if bad == 0:
        print(f"OK: verify-derived hoàn tất, {len(blocks)} blocks đã đối soát, asset_transfers khớp 100% với dữ liệu thô.")
        return 0
    else:
        print(f"THẤT BẠI: verify-derived phát hiện {bad} sai lệch giữa asset_transfers và dữ liệu thô!")
        return 1

def cmd_timeline(a):
    c = db()
    q = ("SELECT b.block_time_utc, b.first_observed_at, b.collected_at, b.number, b.status, t.tx_hash, "
         "t.from_addr, t.to_addr, t.value_raw, r.status FROM transactions t "
         "JOIN blocks b ON b.chain_id=t.chain_id AND b.hash=t.block_hash "
         "LEFT JOIN receipts r ON r.chain_id=t.chain_id AND r.tx_hash=t.tx_hash AND r.block_hash=t.block_hash WHERE 1=1")
    p = []
    if a.from_date:
        q += " AND b.block_timestamp>=?"
        p.append(date_to_ts(a.from_date))
    if a.to_date:
        q += " AND b.block_timestamp<?"
        p.append(date_to_ts(a.to_date) + 86400)
    q += " ORDER BY b.block_timestamp, t.tx_index"
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["block_timestamp_utc", "first_observed_at", "collected_at", "block", "block_status",
                    "tx_hash", "from", "to", "value_wei_raw", "receipt_status"])
        rows = c.execute(q, p).fetchall()
        w.writerows(rows)
    print(f"Đã xuất {len(rows)} dòng -> {a.out} (sha256={hashlib.sha256(open(a.out,'rb').read()).hexdigest()})")

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    p = argparse.ArgumentParser(description="Blockchain Forensics Collector")
    sp = p.add_subparsers(dest="cmd", required=True)

    sp.add_parser("healthcheck").set_defaults(f=cmd_healthcheck)

    b = sp.add_parser("backfill")
    b.set_defaults(f=cmd_backfill)
    b.add_argument("--start-block", type=int, default=0)
    b.add_argument("--end-block", type=int)
    b.add_argument("--from-date")
    b.add_argument("--to-date")
    b.add_argument("--watch-addresses", help="Lọc receipt/logs theo danh sách địa chỉ (phân cách bằng dấu phẩy)")

    c = sp.add_parser("collect")
    c.set_defaults(f=cmd_collect)
    c.add_argument("--start-block", type=int, default=0)
    c.add_argument("--watch-addresses", help="Lọc receipt/logs theo danh sách địa chỉ")

    sp.add_parser("verify").set_defaults(f=cmd_verify)

    vd = sp.add_parser("verify-derived")
    vd.set_defaults(f=cmd_verify_derived)

    vr = sp.add_parser("verify-rpc")
    vr.set_defaults(f=cmd_verify_rpc)
    vr.add_argument("--start-block", type=int, default=0)
    vr.add_argument("--end-block", type=int)

    t = sp.add_parser("timeline")
    t.set_defaults(f=cmd_timeline)
    t.add_argument("--from-date")
    t.add_argument("--to-date")
    t.add_argument("--out", default="timeline.csv")

    a = p.parse_args()
    sys.exit(a.f(a) or 0)

if __name__ == "__main__":
    main()
