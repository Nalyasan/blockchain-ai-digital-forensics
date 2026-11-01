"""Milestone 1 Adversarial Stress Test Suite: Concurrency, Lock-Files, & Error Handling.

Author: Challenger 2 (Milestone 1 Adversarial Challenger)
Scope:
1. Thread Concurrency & Connection Pooling Under Heavy Contention
2. Multiprocess Concurrency Under Heavy Load
3. Lock File Prevention Verification (-wal, -shm, journal) in real_p4.db and WAL-mode databases
4. Robustness to Corrupt, Non-Existent, Relative, and Malformed URIs/Paths
5. Adversarial SQL Bypass & Mutation Attacks (Comments, CTEs, PRAGMAs, Transactions)
"""

import multiprocessing
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path
import pytest

# Ensure worktree root is in sys.path
WORKTREE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKTREE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKTREE_ROOT))

from forensics.ai.db_readonly import (
    ReadOnlyConnection,
    ReadOnlyCursor,
    build_readonly_uri,
    get_readonly_connection,
    readonly_connection,
)

REAL_P4_DB = Path(r"D:\Projest\worktrees\p4_real_integration\data\real_p4.db")
REAL_P4_DATA_DIR = Path(r"D:\Projest\worktrees\p4_real_integration\data")


# Helper top-level function for multiprocessing (must be pickleable)
def _mp_worker_query_task(args):
    db_path_str, num_iterations = args
    from forensics.ai.db_readonly import get_readonly_connection
    conn = get_readonly_connection(db_path_str)
    try:
        results = []
        for _ in range(num_iterations):
            # Query all 5 canonical tables
            c_transfers = conn.execute("SELECT count(*) FROM asset_transfers;").fetchone()[0]
            c_alerts = conn.execute("SELECT count(*) FROM alerts;").fetchone()[0]
            c_blocks = conn.execute("SELECT count(*) FROM blocks;").fetchone()[0]
            c_tx = conn.execute("SELECT count(*) FROM transactions;").fetchone()[0]
            c_calib = conn.execute("SELECT count(*) FROM rule_calibrations;").fetchone()[0]
            results.append((c_transfers, c_alerts, c_blocks, c_tx, c_calib))
        return True, len(results)
    except Exception as exc:
        return False, str(exc)
    finally:
        conn.close()


class TestAdversarialConcurrency:
    """Stress testing thread and process concurrency and connection pooling."""

    def test_concurrent_threads_reading_all_canonical_tables(self):
        """Stress: 50 concurrent threads executing 1,000 queries on all 5 canonical tables."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")

        num_threads = 50
        iterations_per_thread = 20
        total_queries = num_threads * iterations_per_thread * 5

        errors = []

        def worker_task(thread_id):
            try:
                with readonly_connection(REAL_P4_DB) as conn:
                    for _ in range(iterations_per_thread):
                        # Query 1: asset_transfers
                        t_count = conn.execute("SELECT COUNT(*) FROM asset_transfers;").fetchone()[0]
                        assert t_count == 7032
                        # Query 2: alerts
                        a_count = conn.execute("SELECT COUNT(*) FROM alerts;").fetchone()[0]
                        assert a_count == 172
                        # Query 3: blocks
                        b_count = conn.execute("SELECT COUNT(*) FROM blocks;").fetchone()[0]
                        assert b_count == 1789
                        # Query 4: transactions
                        tx_count = conn.execute("SELECT COUNT(*) FROM transactions;").fetchone()[0]
                        assert tx_count == 18
                        # Query 5: rule_calibrations
                        c_count = conn.execute("SELECT COUNT(*) FROM rule_calibrations;").fetchone()[0]
                        assert c_count >= 208

            except Exception as e:
                errors.append((thread_id, str(e)))

        start_time = time.perf_counter()
        threads = [threading.Thread(target=worker_task, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.perf_counter() - start_time

        assert not errors, f"Errors encountered during concurrent thread execution: {errors}"
        # Assert no lock files were generated in data directory
        data_files = [f.name for f in REAL_P4_DATA_DIR.iterdir()]
        assert data_files == ["real_p4.db"], f"Lock files found in {REAL_P4_DATA_DIR}: {data_files}"
        print(f"\n[PASS] 50 threads executed {total_queries} queries in {elapsed:.2f}s (0 errors)")

    def test_high_thread_volume_100_threads(self):
        """Stress: 100 concurrent threads reading canonical tables simultaneously."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")

        num_threads = 100
        errors = []

        def worker_task(tid):
            try:
                with readonly_connection(REAL_P4_DB) as conn:
                    cnt = conn.execute("SELECT count(*) FROM asset_transfers;").fetchone()[0]
                    assert cnt == 7032
            except Exception as e:
                errors.append((tid, str(e)))

        threads = [threading.Thread(target=worker_task, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors in 100-thread test: {errors}"

    def test_unexhausted_cursor_does_not_block_concurrent_readers(self):
        """Stress: Holding an unexhausted cursor on one connection does not block readers on other connections."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")

        # Connection 1 opens a large query but leaves cursor unexhausted
        conn_holding = get_readonly_connection(REAL_P4_DB)
        cursor_holding = conn_holding.cursor()
        cursor_holding.execute("SELECT * FROM asset_transfers;")
        first_row = cursor_holding.fetchone()
        assert first_row is not None

        errors = []

        def concurrent_reader(tid):
            try:
                with readonly_connection(REAL_P4_DB) as conn:
                    cnt = conn.execute("SELECT count(*) FROM alerts;").fetchone()[0]
                    assert cnt == 172
            except Exception as e:
                errors.append((tid, str(e)))

        try:
            # Launch 25 concurrent threads while cursor_holding remains open
            threads = [threading.Thread(target=concurrent_reader, args=(i,)) for i in range(25)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert not errors, f"Unexhausted cursor blocked concurrent readers: {errors}"
        finally:
            cursor_holding.close()
            conn_holding.close()

    def test_thread_churn_rapid_open_close(self):
        """Stress: 20 threads rapidly opening, querying, and closing 200 connections."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")

        num_threads = 20
        cycles = 10
        errors = []

        def churn_task(tid):
            for _ in range(cycles):
                try:
                    conn = get_readonly_connection(REAL_P4_DB)
                    r = conn.execute("SELECT count(*) FROM alerts;").fetchone()[0]
                    assert r == 172
                    conn.close()
                except Exception as e:
                    errors.append((tid, str(e)))

        threads = [threading.Thread(target=churn_task, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during connection churn: {errors}"

    def test_cross_thread_connection_sharing_is_safely_prevented(self):
        """Verify: Sharing a connection across threads triggers OperationalError (safe isolation)."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")

        conn = get_readonly_connection(REAL_P4_DB)
        error_captured = []

        def foreign_thread():
            try:
                conn.execute("SELECT count(*) FROM alerts;")
            except Exception as e:
                error_captured.append(e)

        th = threading.Thread(target=foreign_thread)
        th.start()
        th.join()
        conn.close()

        assert len(error_captured) == 1, "Expected error on cross-thread connection use"
        # ReadOnlyConnection wraps DatabaseError into OperationalError
        err = error_captured[0]
        assert isinstance(err, sqlite3.OperationalError), f"Expected OperationalError, got {type(err)}: {err}"
        assert "SQLite objects created in a thread can only be used in that same thread" in str(err)

    def test_multiprocess_concurrency(self):
        """Stress: Multiple independent OS processes querying real_p4.db concurrently."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")

        num_procs = 4
        iterations_per_proc = 10
        tasks = [(str(REAL_P4_DB), iterations_per_proc) for _ in range(num_procs)]

        with multiprocessing.Pool(processes=num_procs) as pool:
            results = pool.map(_mp_worker_query_task, tasks)

        for success, msg in results:
            assert success is True, f"Multiprocess query failed: {msg}"
            assert msg == iterations_per_proc


class TestLockFileInvariants:
    """Verifies that SQLite lock files (-wal, -shm, journal) are NEVER created."""

    def test_lock_files_never_created_in_real_p4_data_dir(self):
        """Proof: immutable=1 guarantees NO -wal or -shm files are created in data dir."""
        if not REAL_P4_DATA_DIR.exists():
            pytest.skip("real_p4 data dir not found")

        # Record initial state
        initial_files = sorted(f.name for f in REAL_P4_DATA_DIR.iterdir())
        assert initial_files == ["real_p4.db"], f"Initial data dir has unexpected files: {initial_files}"

        observed_extra_files = []
        stop_monitoring = threading.Event()

        def directory_monitor():
            while not stop_monitoring.is_set():
                current_files = [f.name for f in REAL_P4_DATA_DIR.iterdir() if f.name != "real_p4.db"]
                if current_files:
                    observed_extra_files.extend(current_files)
                time.sleep(0.005)

        mon_thread = threading.Thread(target=directory_monitor)
        mon_thread.start()

        try:
            # Execute intensive reads
            with readonly_connection(REAL_P4_DB) as conn:
                for _ in range(50):
                    conn.execute("SELECT * FROM alerts;").fetchall()
                    conn.execute("SELECT * FROM asset_transfers LIMIT 500;").fetchall()
                    conn.execute("SELECT * FROM blocks LIMIT 500;").fetchall()
        finally:
            stop_monitoring.set()
            mon_thread.join()

        final_files = sorted(f.name for f in REAL_P4_DATA_DIR.iterdir())
        assert final_files == ["real_p4.db"], f"Lock files found after test: {final_files}"
        assert not observed_extra_files, f"Lock files observed during test: {observed_extra_files}"

    def test_immutable_prevents_wal_and_shm_even_on_wal_configured_db(self, tmp_path):
        """Proof: On a DB created in WAL mode, immutable=1 prevents creation of -wal or -shm."""
        wal_db = tmp_path / "wal_sample.db"

        # 1. Create a DB in WAL mode with active data
        init_conn = sqlite3.connect(wal_db)
        init_conn.execute("PRAGMA journal_mode = WAL;")
        init_conn.execute("CREATE TABLE test_wal (id INTEGER PRIMARY KEY, msg TEXT);")
        init_conn.execute("INSERT INTO test_wal (msg) VALUES ('first'), ('second');")
        init_conn.commit()
        # Checkpoint and close
        init_conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        init_conn.close()

        # Remove any lingering -wal or -shm files from setup
        for suffix in ["-wal", "-shm"]:
            f = tmp_path / f"wal_sample.db{suffix}"
            if f.exists():
                f.unlink()

        # Confirm only wal_sample.db exists
        files_before = [f.name for f in tmp_path.iterdir()]
        assert "wal_sample.db" in files_before
        assert "wal_sample.db-wal" not in files_before
        assert "wal_sample.db-shm" not in files_before

        # 2. Open via get_readonly_connection (mode=ro&immutable=1)
        conn = get_readonly_connection(wal_db)
        rows = conn.execute("SELECT count(*) FROM test_wal;").fetchone()[0]
        assert rows == 2
        conn.close()

        # 3. Assert NO -wal or -shm files were created by opening/reading
        files_after = [f.name for f in tmp_path.iterdir()]
        assert "wal_sample.db-wal" not in files_after, "SQLite created -wal on immutable connection!"
        assert "wal_sample.db-shm" not in files_after, "SQLite created -shm on immutable connection!"


class TestPathAndCorruptFileHandling:
    """Error propagation and path resolution under edge cases."""

    def test_relative_path_resolution(self):
        """Proof: Relative path resolves to full file URI correctly."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")

        # Compute relative path from current working directory
        rel_path = os.path.relpath(REAL_P4_DB, os.getcwd())
        conn = get_readonly_connection(rel_path)
        try:
            count = conn.execute("SELECT count(*) FROM alerts;").fetchone()[0]
            assert count == 172
        finally:
            conn.close()

    def test_directory_path_raises_operational_error(self, tmp_path):
        """Proof: Passing directory path fails fast with sqlite3.OperationalError."""
        with pytest.raises(sqlite3.OperationalError, match="Database file not found"):
            get_readonly_connection(tmp_path)

    def test_empty_string_path_raises_operational_error(self):
        """Proof: Empty path raises sqlite3.OperationalError."""
        with pytest.raises(sqlite3.OperationalError, match="Database file not found"):
            get_readonly_connection("")

    def test_empty_zero_byte_database_file(self, tmp_path):
        """Proof: Opening a 0-byte database file allows reading 0 tables and rejects write attempts."""
        zero_db = tmp_path / "zero.db"
        zero_db.touch()  # 0 bytes

        conn = get_readonly_connection(zero_db)
        try:
            tables = conn.execute("SELECT name FROM sqlite_master;").fetchall()
            assert len(tables) == 0
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("CREATE TABLE foo (x INT);")
        finally:
            conn.close()

    def test_corrupt_database_file_raises_operational_error(self, tmp_path):
        """Proof: Opening and querying a corrupt non-SQLite file raises OperationalError."""
        corrupt_file = tmp_path / "corrupt.db"
        corrupt_file.write_bytes(b"CORRUPT_NON_SQLITE_HEADER_DATA_1234567890" * 20)

        # Connect succeeds (SQLite lazy-loads pages), but execution must fail with OperationalError
        conn = get_readonly_connection(corrupt_file)
        try:
            with pytest.raises(sqlite3.OperationalError, match="(file is not a database|Database operation rejected)"):
                conn.execute("SELECT * FROM sqlite_master;")
        finally:
            conn.close()

    def test_spaces_and_unicode_in_path(self, tmp_path):
        """Proof: Paths with spaces and Unicode resolve and connect properly."""
        special_dir = tmp_path / "unicode 📁 path" / "sub 測試"
        special_dir.mkdir(parents=True)
        db_file = special_dir / "unicode_test.db"

        # Initialize valid sqlite db
        init_conn = sqlite3.connect(db_file)
        init_conn.execute("CREATE TABLE foo (x INT);")
        init_conn.execute("INSERT INTO foo VALUES (42);")
        init_conn.commit()
        init_conn.close()

        # Open with read-only connector
        conn = get_readonly_connection(db_file)
        try:
            val = conn.execute("SELECT x FROM foo;").fetchone()[0]
            assert val == 42
        finally:
            conn.close()

    def test_malicious_or_corrupt_uri_strings_fail_closed(self):
        """Proof: Passing raw URI strings or URI injection parameters fails closed with OperationalError."""
        malicious_inputs = [
            "file:///D:/some/path/db.sqlite?mode=rw&immutable=0",
            "real_p4.db?mode=rw",
            "sqlite:///test.db",
        ]
        for bad_input in malicious_inputs:
            with pytest.raises(sqlite3.OperationalError, match="Database file not found"):
                get_readonly_connection(bad_input)

    def test_invalid_type_raises_type_error(self):
        """Proof: Passing non-path types raises TypeError fail-closed."""
        with pytest.raises(TypeError):
            get_readonly_connection(None)
        with pytest.raises(TypeError):
            get_readonly_connection(12345)


class TestAdversarialSQLBypass:
    """Adversarially probe SQL bypass techniques to verify defense-in-depth."""

    @pytest.mark.parametrize(
        "sql_bypass",
        [
            # Comment prefix bypasses
            "/* harmless comment */ INSERT INTO alerts (alert_id) VALUES ('evil')",
            "-- harmless comment\nINSERT INTO alerts (alert_id) VALUES ('evil')",
            "/* multi \n line \n comment */ UPDATE alerts SET severity = 'low'",
            # Leading whitespace/newlines/tabs
            "\n\t\r  DELETE FROM alerts WHERE alert_id = '1'",
            # Semicolon leading
            "; INSERT INTO alerts (alert_id) VALUES ('evil')",
            # CTE write bypass
            "WITH del AS (DELETE FROM alerts RETURNING *) SELECT * FROM del;",
            "WITH ins AS (INSERT INTO alerts (alert_id) VALUES ('evil') RETURNING *) SELECT * FROM ins;",
        ],
    )
    def test_sql_bypass_attempts_raise_operational_error(self, sql_bypass):
        """Proof: Every write/DDL bypass attempt raises sqlite3.OperationalError across defense layers."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")

        with readonly_connection(REAL_P4_DB) as conn:
            # Either conn.execute or cursor.execute raises sqlite3.OperationalError
            with pytest.raises(sqlite3.OperationalError):
                conn.execute(sql_bypass)

            cur = conn.cursor()
            with pytest.raises(sqlite3.OperationalError):
                cur.execute(sql_bypass)

    def test_pragma_mutation_attempts_fail_or_are_noop(self):
        """Proof: Attempting PRAGMA writable_schema or journal_mode cannot mutate database or schema."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")

        with readonly_connection(REAL_P4_DB) as conn:
            # 1. Attempt writable_schema PRAGMA
            conn.execute("PRAGMA writable_schema = 1;")
            # Attempt to modify schema through writable_schema must still be blocked by authorizer/wrapper/ro
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("UPDATE sqlite_master SET name = 'hacked' WHERE type = 'table';")

            # 2. Attempt journal_mode PRAGMA
            # In immutable mode, SQLite treats journal_mode change as no-op or returns current mode
            res = conn.execute("PRAGMA journal_mode = DELETE;").fetchone()
            # Verify no journal files were created in data directory
            assert [f.name for f in REAL_P4_DATA_DIR.iterdir()] == ["real_p4.db"]

    def test_database_remains_unmutated_after_attacks(self):
        """Proof: After all adversarial attacks, real_p4.db canonical counts are untouched."""
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")

        with readonly_connection(REAL_P4_DB) as conn:
            assert conn.execute("SELECT count(*) FROM asset_transfers;").fetchone()[0] == 7032
            assert conn.execute("SELECT count(*) FROM alerts;").fetchone()[0] == 172
            assert conn.execute("SELECT count(*) FROM blocks;").fetchone()[0] == 1789
            assert conn.execute("SELECT count(*) FROM transactions;").fetchone()[0] == 18
            assert conn.execute("SELECT count(*) FROM rule_calibrations;").fetchone()[0] >= 208


if __name__ == "__main__":
    pytest.main(["-v", __file__, "--basetemp=C:\\Users\\Naly\\p5_tmp"])
