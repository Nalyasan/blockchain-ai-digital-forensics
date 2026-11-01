"""Milestone 1 Test Suite: Read-Only Database Connection Layer & Invariants.

Verifies:
- Read-only connection using SQLite URI file:<path>?mode=ro&immutable=1
- PRAGMA query_only = ON;
- Explicit rejection (raising OperationalError) on write/DDL attempts across conn, cursor, and scripts
- Canonical dataset verification in real_p4.db (7,032 transfers, 172 alerts, 498 evidence refs)
- G5-02 invariant: zero INSERT OR REPLACE or REPLACE INTO anywhere in forensics/ai/ modules
"""

import ast
import json
import sqlite3
from pathlib import Path
import pytest

from forensics.ai.db_readonly import (
    ReadOnlyConnection,
    ReadOnlyCursor,
    build_readonly_uri,
    get_readonly_connection,
    readonly_connection,
)

REAL_P4_DB = Path(r"D:\Projest\worktrees\p4_real_integration\data\real_p4.db")


class TestDBReadOnlyConnection:
    """Read-Only Database Connection Layer Test Suite."""

    def test_missing_database_raises_operational_error(self, tmp_path):
        """Proof: Missing database file fails fast with sqlite3.OperationalError."""
        fake_db = tmp_path / "non_existent.db"
        with pytest.raises(sqlite3.OperationalError, match="Database file not found"):
            get_readonly_connection(fake_db)

    def test_uri_formatting_ro_and_immutable(self, tmp_path):
        """Proof: URI contains both mode=ro and immutable=1."""
        test_file = tmp_path / "sample.db"
        test_file.touch()
        uri = build_readonly_uri(test_file)
        assert "mode=ro" in uri
        assert "immutable=1" in uri
        assert uri.startswith("file:")

    def test_pragma_query_only_is_on(self):
        """Proof: PRAGMA query_only evaluates to 1 (True)."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            val = conn.execute("PRAGMA query_only;").fetchone()[0]
            assert val == 1, f"Expected PRAGMA query_only=1, got {val}"

    def test_real_p4_row_counts_and_evidence_refs(self):
        """Proof: Verification of 7,032 transfers, 172 alerts, 498 evidence refs in real_p4.db."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            # 1. 7,032 transfers
            transfers_count = conn.execute("SELECT COUNT(*) FROM asset_transfers;").fetchone()[0]
            assert transfers_count == 7032, f"Expected 7,032 asset_transfers, got {transfers_count}"

            # 2. 172 alerts
            alerts_count = conn.execute("SELECT COUNT(*) FROM alerts;").fetchone()[0]
            assert alerts_count == 172, f"Expected 172 alerts, got {alerts_count}"

            # 3. 498 evidence refs across alerts
            rows = conn.execute("SELECT alert_id, evidence_refs FROM alerts;").fetchall()
            total_refs = 0
            for row in rows:
                refs_json = row["evidence_refs"]
                if refs_json:
                    parsed = json.loads(refs_json)
                    total_refs += len(parsed) if isinstance(parsed, list) else 1
            assert total_refs == 498, f"Expected 498 evidence_refs in alerts, got {total_refs}"

    @pytest.mark.parametrize(
        "write_sql",
        [
            "INSERT INTO asset_transfers (chain_id) VALUES (1)",
            "INSERT OR REPLACE INTO alerts (alert_id) VALUES ('evil')",
            "REPLACE INTO alerts (alert_id) VALUES ('evil')",
            "INSERT OR IGNORE INTO asset_transfers (chain_id) VALUES (1)",
            "UPDATE alerts SET severity = 'low' WHERE alert_id = '1'",
            "DELETE FROM alerts WHERE alert_id = '1'",
            "CREATE TABLE test_evil (id INT)",
            "DROP TABLE alerts",
            "ALTER TABLE alerts ADD COLUMN evil TEXT",
            "ATTACH DATABASE ':memory:' AS attached_db",
            "VACUUM",
        ],
    )
    def test_all_write_ddl_attempts_raise_operational_error_on_conn(self, write_sql):
        """Proof: conn.execute rejects write/DDL attempts with sqlite3.OperationalError."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            with pytest.raises(sqlite3.OperationalError):
                conn.execute(write_sql)

    @pytest.mark.parametrize(
        "write_sql",
        [
            "INSERT INTO asset_transfers (chain_id) VALUES (1)",
            "INSERT OR REPLACE INTO alerts (alert_id) VALUES ('evil')",
            "REPLACE INTO alerts (alert_id) VALUES ('evil')",
            "INSERT OR IGNORE INTO asset_transfers (chain_id) VALUES (1)",
            "UPDATE alerts SET severity = 'low' WHERE alert_id = '1'",
            "DELETE FROM alerts WHERE alert_id = '1'",
            "CREATE TABLE test_evil (id INT)",
            "DROP TABLE alerts",
            "ALTER TABLE alerts ADD COLUMN evil TEXT",
            "ATTACH DATABASE ':memory:' AS attached_db",
            "VACUUM",
        ],
    )
    def test_all_write_ddl_attempts_raise_operational_error_on_cursor(self, write_sql):
        """Proof: cursor.execute rejects write/DDL attempts with sqlite3.OperationalError."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            cur = conn.cursor()
            with pytest.raises(sqlite3.OperationalError):
                cur.execute(write_sql)

    def test_executemany_rejects_modifications(self):
        """Proof: executemany rejects modifying statements with OperationalError."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            with pytest.raises(sqlite3.OperationalError):
                conn.executemany(
                    "INSERT INTO alerts (alert_id) VALUES (?)",
                    [("x1",), ("x2",)],
                )
            cur = conn.cursor()
            with pytest.raises(sqlite3.OperationalError):
                cur.executemany(
                    "INSERT INTO alerts (alert_id) VALUES (?)",
                    [("x1",), ("x2",)],
                )

    def test_executescript_rejects_modifications(self):
        """Proof: executescript with modifying statements raises OperationalError."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            script = "SELECT 1; INSERT INTO alerts (alert_id) VALUES ('x');"
            with pytest.raises(sqlite3.OperationalError):
                conn.executescript(script)
            cur = conn.cursor()
            with pytest.raises(sqlite3.OperationalError):
                cur.executescript(script)

    def test_pragma_query_only_off_does_not_enable_writes(self):
        """Proof: Even if PRAGMA query_only = OFF is executed, writes still fail due to mode=ro."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            # Query only toggle is allowed or rejected by authorizer, but in either case writes are blocked
            try:
                conn.execute("PRAGMA query_only = OFF;")
            except (sqlite3.OperationalError, sqlite3.DatabaseError):
                pass
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("INSERT INTO alerts (alert_id) VALUES ('fail')")

    def test_connection_and_cursor_type_invariants(self):
        """Proof: Returned connection and cursor are instances of sqlite3 standard classes."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            assert isinstance(conn, sqlite3.Connection)
            assert isinstance(conn, ReadOnlyConnection)
            cur = conn.cursor()
            assert isinstance(cur, sqlite3.Cursor)
            assert isinstance(cur, ReadOnlyCursor)

    def test_zero_insert_or_replace_invariant_in_ai_modules(self):
        """Proof: G5-02 invariant - zero occurrences of INSERT OR REPLACE or REPLACE INTO in forensics/ai."""
        ai_dir = Path("forensics/ai")
        if not ai_dir.exists():
            pytest.skip("forensics/ai directory not yet populated")
        for py_file in ai_dir.glob("*.py"):
            content = py_file.read_text(encoding="utf-8").upper()
            assert "INSERT OR REPLACE" not in content, (
                f"Forbidden 'INSERT OR REPLACE' found in {py_file.name}"
            )
            assert "REPLACE INTO" not in content, (
                f"Forbidden 'REPLACE INTO' found in {py_file.name}"
            )
            assert "INSERT OR IGNORE" not in content, (
                f"Forbidden 'INSERT OR IGNORE' found in {py_file.name}"
            )

    def test_ast_inspection_ai_modules_syntax_validity(self):
        """Proof: All python files in forensics/ai are syntactically valid ASTs."""
        ai_dir = Path("forensics/ai")
        if not ai_dir.exists():
            pytest.skip("forensics/ai directory not yet populated")
        for py_file in ai_dir.glob("*.py"):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            assert isinstance(tree, ast.Module)
