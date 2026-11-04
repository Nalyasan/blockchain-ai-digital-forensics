"""Adversarial Stress Test Suite for Read-Only SQLite Connector.

Authored by Milestone 1 Adversarial Challenger 1.
Adversarially challenges the defense-in-depth layers of db_readonly.py:
1. Regex filter bypasses (comments, whitespace, casing, CTEs)
2. Authorizer bypass attempts (temp objects, attach/detach, DDL)
3. PRAGMA tamper attempts (query_only=OFF, writable_schema, journal_mode, etc.)
4. Multi-statement script injection
5. Defense-in-depth isolation: authorizer layer vs VFS immutable layer
6. Bitwise immutability verification of real_p4.db before and after stress tests.
"""

import hashlib
import os
from pathlib import Path
import sqlite3
import pytest

from forensics.ai.db_readonly import (
    ReadOnlyConnection,
    ReadOnlyCursor,
    build_readonly_uri,
    get_readonly_connection,
    readonly_connection,
)
from forensics.paths import REAL_P4_DB as CANONICAL_REAL_P4_DB

REAL_P4_DB = CANONICAL_REAL_P4_DB if CANONICAL_REAL_P4_DB.exists() else Path(r"D:\Projest\worktrees\p4_real_integration\data\real_p4.db")
EXPECTED_REAL_P4_SHA256 = "6bd9aed48ac2742d0862198bff65994861244ec681dc8abeb3e6f771e7808c97"
EXPECTED_REAL_P4_SIZE = 5947392


def get_db_sha256(path: Path) -> str:
    """Computes SHA-256 hash of the target database file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class TestAdversarialDDLAndMutations:
    """Adversarially probe write/DDL attempts with evasive formatting."""

    @pytest.mark.parametrize(
        "sql",
        [
            # Standard DDL & Writes
            "INSERT INTO alerts (alert_id) VALUES ('adv_1')",
            "UPDATE alerts SET severity = 'critical' WHERE alert_id = '1'",
            "DELETE FROM alerts WHERE alert_id = '1'",
            "REPLACE INTO alerts (alert_id) VALUES ('adv_2')",
            "DROP TABLE alerts",
            "ALTER TABLE alerts ADD COLUMN pwned TEXT",
            "CREATE TABLE pwned (id INT)",
            "CREATE INDEX pwned_idx ON alerts (alert_id)",
            "DROP INDEX IF EXISTS pwned_idx",
            "CREATE VIEW pwned_v AS SELECT * FROM alerts",
            "DROP VIEW IF EXISTS pwned_v",
            "CREATE TRIGGER pwned_trig AFTER INSERT ON alerts BEGIN SELECT 1; END",
            "DROP TRIGGER IF EXISTS pwned_trig",
            "VACUUM",
            "REINDEX",
            # Temp Objects
            "CREATE TEMP TABLE temp_pwned (id INT)",
            "CREATE TEMPORARY TABLE temp_pwned2 (id INT)",
            "CREATE TEMP VIEW temp_pwned_v AS SELECT 1",
            "CREATE TEMP TRIGGER temp_pwned_trig AFTER INSERT ON alerts BEGIN SELECT 1; END",
            # Database Attach / Detach
            "ATTACH DATABASE ':memory:' AS evil_db",
            "ATTACH ':memory:' AS evil_db",
            "DETACH DATABASE evil_db",
            "DETACH evil_db",
            # Comment Evasions (bypassing naive regexes)
            "/* inline comment */ INSERT INTO alerts (alert_id) VALUES ('adv_c1')",
            "/* multiline\ncomment */ DROP TABLE alerts",
            "-- single line comment\nDELETE FROM alerts",
            "-- single line comment\r\nUPDATE alerts SET severity = 'high'",
            "/**/CREATE TABLE temp_bypass (id INT)",
            "/* leading *//* second */ VACUUM",
            # CTE Writes
            "WITH evil_cte AS (SELECT 'adv_cte') INSERT INTO alerts (alert_id) SELECT * FROM evil_cte",
            "WITH evil_cte AS (SELECT 1) DELETE FROM alerts WHERE alert_id = '1'",
            # Leading Whitespace & Control Characters
            "\t\t\n  INSERT INTO alerts (alert_id) VALUES ('adv_ws')",
            "\r\n\tDROP TABLE alerts",
            "\x0cCREATE TABLE evil (id INT)",
            # Case variations
            "iNsErT InTo alerts (alert_id) VALUES ('adv_case')",
            "dRoP tAbLe alerts",
            "vAcUuM",
            # Extension loading
            "SELECT load_extension('nonexistent_ext')",
            # EXPLAIN write
            "EXPLAIN INSERT INTO alerts (alert_id) VALUES ('adv_explain')",
            "EXPLAIN QUERY PLAN DELETE FROM alerts",
        ],
    )
    def test_adversarial_queries_fail_closed_on_conn(self, sql):
        """Proof: Every adversarial query raises sqlite3.OperationalError on conn.execute."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            with pytest.raises(sqlite3.OperationalError):
                conn.execute(sql)

    @pytest.mark.parametrize(
        "sql",
        [
            "/* comment */ INSERT INTO alerts (alert_id) VALUES ('adv_cur1')",
            "/* comment */ DROP TABLE alerts",
            "CREATE TEMP TABLE temp_cur (id INT)",
            "ATTACH ':memory:' AS cur_evil",
            "WITH x AS (SELECT 1) DELETE FROM alerts",
        ],
    )
    def test_adversarial_queries_fail_closed_on_cursor(self, sql):
        """Proof: Every adversarial query raises sqlite3.OperationalError on cursor.execute."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            cur = conn.cursor()
            with pytest.raises(sqlite3.OperationalError):
                cur.execute(sql)

    def test_multi_statement_injections_in_executescript(self):
        """Proof: executescript with comment-hidden attacks is rejected."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            scripts = [
                "SELECT 1; /* hidden */ INSERT INTO alerts (alert_id) VALUES ('script_evil');",
                "SELECT 1;\n-- hidden\nDELETE FROM alerts WHERE alert_id = '1';",
                "SELECT 1; /* hidden */ CREATE TEMP TABLE evil_tmp (id INT);",
                "SELECT 1; /* hidden */ ATTACH DATABASE ':memory:' AS evil_s;",
                "SELECT 1; /* hidden */ VACUUM;",
                "SELECT 1; /* hidden */ UPDATE alerts SET severity = 'critical';",
            ]
            for script in scripts:
                with pytest.raises(sqlite3.OperationalError):
                    conn.executescript(script)
                cur = conn.cursor()
                with pytest.raises(sqlite3.OperationalError):
                    cur.executescript(script)


class TestAdversarialPragmaTampering:
    """Adversarially probe PRAGMA tampering to bypass read-only enforcement."""

    def test_pragma_query_only_toggle_leaves_vfs_intact(self):
        """Proof: PRAGMA query_only = OFF does not permit mutations."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            conn.execute("PRAGMA query_only = OFF;")
            # 1. Regex rejects direct keyword
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("INSERT INTO alerts (alert_id) VALUES ('fail')")
            # 2. Authorizer rejects comment-hidden keyword
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("/* comment */ INSERT INTO alerts (alert_id) VALUES ('fail')")

    def test_pragma_writable_schema_leaves_vfs_intact(self):
        """Proof: PRAGMA writable_schema = ON does not permit schema corruption."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            conn.execute("PRAGMA writable_schema = ON;")
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("UPDATE sqlite_master SET sql = 'corrupt'")
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("/* comment */ UPDATE sqlite_master SET sql = 'corrupt'")

    def test_pragma_mutation_commands_fail_or_no_op(self):
        """Proof: Disk-modifying PRAGMAs either raise OperationalError or are non-operational."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            # Modifying header values fails at VFS layer
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("PRAGMA user_version = 999;")
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("PRAGMA application_id = 999;")
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("PRAGMA optimize;")
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("PRAGMA incremental_vacuum;")

            # Journal mode cannot be changed on immutable read-only db
            conn.execute("PRAGMA journal_mode = WAL;")
            current_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
            assert current_mode == "delete", f"Journal mode unexpectedly changed to {current_mode}"


class TestDefenseInDepthIsolation:
    """Stress-test individual defense layers when higher layers are explicitly stripped."""

    def test_authorizer_catches_comment_bypasses(self):
        """Proof: When Python regex is bypassed via comments, the Authorizer layer still blocks with OperationalError."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            # SQL starts with '/*' so _WRITE_KEYWORDS_REGEX does not match, but authorizer rejects
            with pytest.raises(sqlite3.OperationalError, match=r"(Database operation rejected|not authorized|Script execution rejected)"):
                conn.execute("/* bypass regex */ INSERT INTO alerts (alert_id) VALUES ('authorizer_test')")

    def test_vfs_catches_removed_authorizer(self):
        """Proof: If authorizer is removed, SQLite VFS mode=ro&immutable=1 still halts write with OperationalError."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            conn.set_authorizer(None)
            # Both regex and authorizer bypassed, C VFS must reject
            with pytest.raises(sqlite3.OperationalError, match=r"attempt to write a readonly database"):
                conn.execute("/* bypass regex & authorizer */ INSERT INTO alerts (alert_id) VALUES ('vfs_test')")

    def test_raw_cursor_cannot_write(self):
        """Proof: Even if an unadorned sqlite3.Cursor is instantiated, authorizer and VFS block writes."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        with readonly_connection(REAL_P4_DB) as conn:
            raw_cur = conn.cursor(factory=sqlite3.Cursor)
            assert type(raw_cur) is sqlite3.Cursor
            with pytest.raises(sqlite3.DatabaseError):
                raw_cur.execute("/* bypass */ INSERT INTO alerts (alert_id) VALUES ('raw_test')")


class TestBitwiseImmutabilityAndZeroArtifacts:
    """Verify bitwise immutability and lack of artifact creation before and after stress tests."""

    def test_pre_and_post_stress_bitwise_hash_identical(self):
        """Proof: real_p4.db is 100% bitwise identical before and after intense stress tests."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")

        # 1. Pre-condition check
        pre_hash = get_db_sha256(REAL_P4_DB)
        assert pre_hash == EXPECTED_REAL_P4_SHA256, f"Baseline hash mismatch: {pre_hash}"
        assert REAL_P4_DB.stat().st_size == EXPECTED_REAL_P4_SIZE

        # 2. Run high-volume adversarial barrage
        with readonly_connection(REAL_P4_DB) as conn:
            for i in range(100):
                try:
                    conn.execute(f"/* attack {i} */ INSERT INTO alerts (alert_id) VALUES ('barrage_{i}')")
                except sqlite3.OperationalError:
                    pass
                try:
                    conn.execute(f"/* attack {i} */ DROP TABLE alerts")
                except sqlite3.OperationalError:
                    pass

        # 3. Post-condition check: SHA256 must be identical
        post_hash = get_db_sha256(REAL_P4_DB)
        assert post_hash == EXPECTED_REAL_P4_SHA256, (
            f"MUTATION DETECTED! Expected {EXPECTED_REAL_P4_SHA256}, got {post_hash}"
        )
        assert REAL_P4_DB.stat().st_size == EXPECTED_REAL_P4_SIZE

        # 4. Zero sidecar files (.db-wal, .db-shm, .db-journal) in data directory
        data_dir = REAL_P4_DB.parent
        sidecar_files = list(data_dir.glob("real_p4.db-*"))
        assert len(sidecar_files) == 0, f"Unwanted sidecar files detected: {sidecar_files}"
