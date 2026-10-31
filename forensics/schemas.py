"""Quản lý Schema SQLite tập trung cho toàn bộ hệ thống Blockchain Forensics (Mục 6.2).
Là NGUỒN DUY NHẤT định nghĩa cấu trúc bảng SQLite.
"""
import os, sqlite3, logging

log = logging.getLogger("forensics.schemas")

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

CREATE TABLE IF NOT EXISTS alerts(
  alert_id TEXT PRIMARY KEY, rule_id TEXT, rule_version TEXT, unit_type TEXT, unit_key TEXT,
  asset_id TEXT, severity TEXT, score REAL, reason TEXT, evidence_refs TEXT,
  window_start TEXT, window_end TEXT, created_at TEXT, status TEXT DEFAULT 'new'
);

CREATE TABLE IF NOT EXISTS analysis_runs(
  analysis_id TEXT PRIMARY KEY, provider TEXT, model_name TEXT, prompt_version TEXT,
  tool_calls_log TEXT, input_refs TEXT, output_json TEXT, existence_ref_ratio REAL,
  content_match_ratio REAL, injection_detected INTEGER NOT NULL DEFAULT 0,
  temperature REAL, seed INT, created_at TEXT
);

CREATE TABLE IF NOT EXISTS evidence_exports(
  export_id TEXT PRIMARY KEY, case_id TEXT, manifest_path TEXT, manifest_sha256 TEXT,
  storage_uri TEXT, created_at TEXT, operator TEXT, onchain_evidence_id INT
);

CREATE TABLE IF NOT EXISTS custody_events(
  event_id TEXT PRIMARY KEY, evidence_id INT, case_id TEXT, action INT,
  actor_address TEXT, artifact_sha256 TEXT, note_hash TEXT, chain_id INT,
  contract_address TEXT, tx_hash TEXT, block_number INT, recorded_at TEXT,
  verified INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS reviews(
  review_id TEXT PRIMARY KEY, alert_id TEXT, reviewer TEXT, verdict TEXT,
  rationale TEXT, reviewed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_blocks_time ON blocks(block_timestamp);
CREATE INDEX IF NOT EXISTS idx_tx_from ON transactions(from_addr);
CREATE INDEX IF NOT EXISTS idx_tx_to ON transactions(to_addr);
CREATE INDEX IF NOT EXISTS idx_transfers_from ON asset_transfers(from_addr);
CREATE INDEX IF NOT EXISTS idx_transfers_to ON asset_transfers(to_addr);
CREATE INDEX IF NOT EXISTS idx_transfers_asset ON asset_transfers(asset_id);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(window_start);
CREATE INDEX IF NOT EXISTS idx_exports_case ON evidence_exports(case_id);
"""

GROUP3_SCHEMA = """
CREATE TABLE IF NOT EXISTS anchor_links(
  chain_id INTEGER NOT NULL,
  contract_address TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL,
  evidence_id INTEGER NOT NULL,
  tx_hash TEXT NOT NULL,
  log_index INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  recorded_at TEXT NOT NULL,
  PRIMARY KEY(chain_id, contract_address, manifest_sha256)
);

CREATE TABLE IF NOT EXISTS onchain_operations(
  operation_id TEXT PRIMARY KEY,
  op_type TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  intent_canonical TEXT NOT NULL,
  state TEXT NOT NULL,
  chain_id INTEGER NOT NULL,
  contract_address TEXT NOT NULL,
  signer TEXT NOT NULL,
  tx_hash TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS onchain_operation_events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  operation_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  from_state TEXT,
  to_state TEXT NOT NULL,
  code TEXT NOT NULL
);
"""

GROUP3_TABLES = ("anchor_links", "onchain_operations", "onchain_operation_events")


def _table_columns(c, table):
    return {row[1] for row in c.execute("PRAGMA table_info(" + table + ")").fetchall()}


def migrate_group3(c):
    """Additive Group 3 tables/columns. Safe on copies; does not rewrite custody history.

    Guarantees true transaction atomicity using SQLite SAVEPOINT without implicit commits
    from executescript().
    """
    c.execute("SAVEPOINT migrate_group3")
    try:
        for stmt in GROUP3_SCHEMA.strip().split(";"):
            sql = stmt.strip()
            if sql:
                c.execute(sql)
        cols = _table_columns(c, "custody_events")
        if cols and "log_index" not in cols:
            c.execute("ALTER TABLE custody_events ADD COLUMN log_index INTEGER")
        if cols and "event_type" not in cols:
            c.execute("ALTER TABLE custody_events ADD COLUMN event_type TEXT")
        if cols:
            c.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_custody_event_identity "
                "ON custody_events(chain_id, contract_address, tx_hash, log_index)"
            )
        c.execute("RELEASE migrate_group3")
    except Exception:
        c.execute("ROLLBACK TO migrate_group3")
        c.execute("RELEASE migrate_group3")
        raise


def rollback_group3(c):
    """Drop Group 3 additive objects only. Never deletes historical custody/export rows."""
    c.execute("DROP INDEX IF EXISTS idx_custody_event_identity")
    for table in ("onchain_operation_events", "onchain_operations", "anchor_links"):
        c.execute("DROP TABLE IF EXISTS " + table)
    cols = _table_columns(c, "custody_events")
    for column in ("log_index", "event_type"):
        if column in cols:
            try:
                c.execute("ALTER TABLE custody_events DROP COLUMN " + column)
            except sqlite3.OperationalError:
                log.info("Không DROP được cột custody_events.%s; giữ nguyên", column)


def group3_schema_present(c):
    names = {row[0] for row in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN (?,?,?)", GROUP3_TABLES
    ).fetchall()}
    return names == set(GROUP3_TABLES)


def migrate_db(c):
    """Đảm bảo các DB cũ được nâng cấp lên schema đầy đủ mà không làm mất dữ liệu."""
    # 1. Thêm cột synthetic vào blocks nếu thiếu
    cols = [r[1] for r in c.execute("PRAGMA table_info(blocks)").fetchall()]
    if cols and "synthetic" not in cols:
        c.execute("ALTER TABLE blocks ADD COLUMN synthetic INTEGER NOT NULL DEFAULT 0")
        log.info("Đã migrate: thêm cột synthetic vào bảng blocks")

    # 2. Tạo các bảng và index còn thiếu nếu chưa có
    c.executescript(SCHEMA)
    migrate_group3(c)

def init_db(path):
    """Khởi tạo hoặc kết nối DB, thực thi migration và trả về đối tượng kết nối sqlite3."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    c = sqlite3.connect(path)
    c.executescript(SCHEMA)
    migrate_db(c)
    return c
