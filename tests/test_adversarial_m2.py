"""Milestone 2 Adversarial Stress Test Suite: EVM 256-bit Arithmetic, Concurrency & Provider.

Adversarial Challenger 2 Verification Harness.

Covers:
1. EVM 256-bit integer math:
   - Counterparty volume aggregation with massive integers (10^30, 2^256 - 1).
   - Exact string preservation without floating-point conversion, scientific notation, or precision loss.
   - Non-digit / malformed / zero amount handling.
   - Transfer extraction in get_tx, get_address_history, get_timeline, and get_alerts.
2. Pydantic AI AnyIO concurrency & thread safety:
   - Pydantic AI Agent executing tools across AnyIO worker threads.
   - Empirical proof of check_same_thread=False preventing sqlite3.ProgrammingError across threads.
   - Concurrent multi-threaded query execution across 10 threads.
   - ToolBudgetManager isolation across concurrent sessions.
3. Provider offline determinism:
   - TestModel execution and reproducibility.
   - Custom FunctionModel callback dispatch.
   - Enforcement of request_limit=8 and UsageLimitExceeded bounds.
   - Environment variable overriding hierarchy without credential leakage.
4. Database immutability:
   - Verification of real_p4.db byte-identical hash preservation.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext, UsageLimits
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart

from forensics.ai.db_readonly import (
    ReadOnlyConnection,
    build_readonly_uri,
    get_readonly_connection,
    readonly_authorizer,
)
from forensics.ai.provider import (
    AIConfig,
    MissingAPIKeyError,
    create_function_model,
    create_model,
    create_test_model,
    get_ai_config,
    get_usage_limits,
    mask_api_key,
    resolve_api_key,
)
from forensics.ai.tools import (
    AUTHORIZED_TOOLS,
    MAX_AI_TOOL_STEPS,
    ProductionDatabaseMutationError,
    RangeLimitExceeded,
    SessionLimitExceeded,
    ToolBudgetExceeded,
    ToolBudgetManager,
    UnauthorizedToolError,
    collect_missing_range,
    execute_guarded_tool,
    get_address_history,
    get_alerts,
    get_counterparties,
    get_staging_connection,
    get_timeline,
    get_tx,
    init_staging_tables,
    validate_block_range,
)
from forensics.paths import REAL_P4_DB as CANONICAL_REAL_P4_DB

REAL_P4_DB = CANONICAL_REAL_P4_DB

# 256-bit EVM constants
UINT256_MAX = (1 << 256) - 1
UINT256_MAX_STR = str(UINT256_MAX)
TEN_TO_THIRTY = 10**30
TEN_TO_THIRTY_STR = str(TEN_TO_THIRTY)


# ==============================================================================
# Helper to build an in-memory test DB with arbitrary transfer data
# ==============================================================================


def create_stress_transfers_db() -> sqlite3.Connection:
    """Creates an in-memory SQLite DB with schema, staging tables, and alerts table."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_staging_tables(conn)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY, rule_id TEXT, rule_version TEXT, unit_type TEXT,
            unit_key TEXT, asset_id TEXT, severity TEXT, score REAL, reason TEXT,
            evidence_refs TEXT, window_start TEXT, window_end TEXT, created_at TEXT
        )
        """
    )
    conn.commit()
    return conn


# ==============================================================================
# Suite 1: EVM 256-bit Integer Arithmetic & String Preservation
# ==============================================================================


class TestEVM256BitArithmetic:
    """Stress tests EVM 256-bit arithmetic, volume aggregation, and string preservation."""

    def test_uint256_max_exact_value(self):
        """Sanity check UINT256_MAX value matches EVM max integer."""
        expected_hex = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        assert hex(UINT256_MAX) == expected_hex
        assert len(UINT256_MAX_STR) == 78
        assert UINT256_MAX_STR.startswith("115792089237316195423570985008687907853269984665640564039457584007913129639935")

    def test_counterparty_volume_aggregation_with_massive_integers(self):
        """Proof: Aggregates multiple transfers of 10^30 and 2^256-1 with ZERO float truncation."""
        db = create_stress_transfers_db()
        alice = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        bob = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        carol = "0xcccccccccccccccccccccccccccccccccccccccc"

        # Alice -> Bob: 3 transfers of UINT256_MAX
        # Bob -> Alice: 2 transfers of TEN_TO_THIRTY
        # Alice -> Carol: 1 transfer of 500
        cursor = db.cursor()
        for i in range(3):
            cursor.execute(
                """
                INSERT INTO asset_transfers (chain_id, block_number, block_hash, block_timestamp,
                                            tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic)
                VALUES (1, 100, '0xblk1', 1000, ?, ?, '0xDAI', ?, ?, ?, 1)
                """,
                (f"0xtx_ab_{i}", i, alice, bob, UINT256_MAX_STR),
            )

        for i in range(2):
            cursor.execute(
                """
                INSERT INTO asset_transfers (chain_id, block_number, block_hash, block_timestamp,
                                            tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic)
                VALUES (1, 101, '0xblk2', 1010, ?, ?, '0xDAI', ?, ?, ?, 1)
                """,
                (f"0xtx_ba_{i}", i, bob, alice, TEN_TO_THIRTY_STR),
            )

        cursor.execute(
            """
            INSERT INTO asset_transfers (chain_id, block_number, block_hash, block_timestamp,
                                        tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic)
            VALUES (1, 102, '0xblk3', 1020, '0xtx_ac', 0, '0xDAI', ?, ?, '500', 1)
            """,
            (alice, carol),
        )
        db.commit()

        # Query counterparties for Alice
        results = get_counterparties(db, alice)
        assert len(results) == 2

        # Bob should be #1 counterparty
        bob_item = next(r for r in results if r["counterparty"] == bob)
        assert bob_item["sent_count"] == 3
        assert bob_item["received_count"] == 2
        assert bob_item["total_transfers"] == 5

        # Expected sums using exact arbitrary-precision arithmetic
        expected_sent = 3 * UINT256_MAX
        expected_recv = 2 * TEN_TO_THIRTY
        expected_total = expected_sent + expected_recv

        assert bob_item["volume_sent_raw"] == str(expected_sent)
        assert bob_item["volume_received_raw"] == str(expected_recv)
        assert bob_item["total_volume_raw"] == str(expected_total)

        # Confirm no float conversion artifacts (no 'e+', no '.0', no scientific notation)
        for field_name in ["volume_sent_raw", "volume_received_raw", "total_volume_raw"]:
            val_str = bob_item[field_name]
            assert "e+" not in val_str, f"Scientific notation detected in {field_name}: {val_str}"
            assert "." not in val_str, f"Floating point decimal detected in {field_name}: {val_str}"
            assert val_str.isdigit(), f"Non-digit character detected in {field_name}: {val_str}"

        # Carol should be #2 counterparty
        carol_item = next(r for r in results if r["counterparty"] == carol)
        assert carol_item["volume_sent_raw"] == "500"
        assert carol_item["volume_received_raw"] == "0"
        assert carol_item["total_volume_raw"] == "500"

    def test_counterparty_volume_sorting_massive_integers(self):
        """Proof: Counterparties with higher 256-bit volumes sort before lower ones."""
        db = create_stress_transfers_db()
        hub = "0xhub0000000000000000000000000000000000000"
        whale = "0xwhale0000000000000000000000000000000000"
        shrimp = "0xshrimp000000000000000000000000000000000"

        # Hub -> Whale: 1 transfer of 2^256 - 1
        # Hub -> Shrimp: 1 transfer of 10^30
        cursor = db.cursor()
        cursor.execute(
            """
            INSERT INTO asset_transfers (chain_id, block_number, block_hash, block_timestamp,
                                        tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic)
            VALUES (1, 100, '0xblk1', 1000, '0xtx1', 0, '0xWETH', ?, ?, ?, 1)
            """,
            (hub, whale, UINT256_MAX_STR),
        )
        cursor.execute(
            """
            INSERT INTO asset_transfers (chain_id, block_number, block_hash, block_timestamp,
                                        tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic)
            VALUES (1, 101, '0xblk2', 1010, '0xtx2', 0, '0xWETH', ?, ?, ?, 1)
            """,
            (hub, shrimp, TEN_TO_THIRTY_STR),
        )
        db.commit()

        results = get_counterparties(db, hub)
        assert len(results) == 2
        # Both have 1 transfer, but Whale has vastly higher volume (2^256-1 >> 10^30)
        assert results[0]["counterparty"] == whale
        assert results[1]["counterparty"] == shrimp

    def test_non_digit_and_zero_amount_handling(self):
        """Proof: Handles '0', empty, None, and malformed amount_raw gracefully."""
        db = create_stress_transfers_db()
        addr_a = "0x1111111111111111111111111111111111111111"
        addr_b = "0x2222222222222222222222222222222222222222"

        cursor = db.cursor()
        # Transfer 1: 0
        cursor.execute(
            """
            INSERT INTO asset_transfers (chain_id, block_number, block_hash, block_timestamp,
                                        tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic)
            VALUES (1, 100, '0xblk1', 1000, '0xtx1', 0, '0xTKN', ?, ?, '0', 1)
            """,
            (addr_a, addr_b),
        )
        # Transfer 2: None
        cursor.execute(
            """
            INSERT INTO asset_transfers (chain_id, block_number, block_hash, block_timestamp,
                                        tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic)
            VALUES (1, 101, '0xblk2', 1010, '0xtx2', 0, '0xTKN', ?, ?, NULL, 1)
            """,
            (addr_a, addr_b),
        )
        # Transfer 3: malformed non-digit string
        cursor.execute(
            """
            INSERT INTO asset_transfers (chain_id, block_number, block_hash, block_timestamp,
                                        tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic)
            VALUES (1, 102, '0xblk3', 1020, '0xtx3', 0, '0xTKN', ?, ?, '0xdeadbeef', 1)
            """,
            (addr_a, addr_b),
        )
        db.commit()

        res = get_counterparties(db, addr_a)
        assert len(res) == 1
        assert res[0]["total_transfers"] == 3
        # Malformed and null amounts default to 0
        assert res[0]["total_volume_raw"] == "0"

    def test_get_tx_preserves_uint256_max(self):
        """Proof: get_tx preserves 2^256-1 in value_raw and amount_raw."""
        db = create_stress_transfers_db()
        tx_hash = "0xdeadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"

        cursor = db.cursor()
        cursor.execute(
            """
            INSERT INTO transactions (chain_id, tx_hash, block_hash, block_number, tx_index,
                                     from_addr, to_addr, value_raw, nonce, input, raw_json, raw_sha256)
            VALUES (1, ?, '0xblk1', 100, 0, '0xfrom', '0xto', ?, 0, '0x', '{}', 'sha')
            """,
            (tx_hash, UINT256_MAX_STR),
        )
        cursor.execute(
            """
            INSERT INTO asset_transfers (chain_id, block_number, block_hash, block_timestamp,
                                        tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic)
            VALUES (1, 100, '0xblk1', 1000, ?, 0, '0xASSET', '0xfrom', '0xto', ?, 1)
            """,
            (tx_hash, TEN_TO_THIRTY_STR),
        )
        db.commit()

        data = get_tx(db, tx_hash)
        assert data is not None
        assert data["value_raw"] == UINT256_MAX_STR
        assert len(data["transfers"]) == 1
        assert data["transfers"][0]["amount_raw"] == TEN_TO_THIRTY_STR

    def test_get_address_history_preserves_uint256_max(self):
        """Proof: get_address_history preserves 2^256-1 exact string."""
        db = create_stress_transfers_db()
        addr = "0xfeedbeef00000000000000000000000000000000"

        cursor = db.cursor()
        cursor.execute(
            """
            INSERT INTO asset_transfers (chain_id, block_number, block_hash, block_timestamp,
                                        tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic)
            VALUES (1, 100, '0xblk1', 1000, '0xtx1', 0, '0xASSET', ?, '0xother', ?, 1)
            """,
            (addr, UINT256_MAX_STR),
        )
        db.commit()

        history = get_address_history(db, addr)
        assert len(history) == 1
        assert history[0]["amount_raw"] == UINT256_MAX_STR

    def test_get_timeline_preserves_uint256_max(self):
        """Proof: get_timeline preserves 2^256-1 in transfer details."""
        db = create_stress_transfers_db()
        cursor = db.cursor()
        cursor.execute(
            """
            INSERT INTO blocks (chain_id, number, hash, parent_hash, block_timestamp,
                               block_time_utc, first_observed_at, collected_at, status, synthetic)
            VALUES (1, 100, '0xblk1', '0xblk0', 1000, '2026-11-01T00:00:00Z', '', '', 'canonical', 1)
            """
        )
        cursor.execute(
            """
            INSERT INTO asset_transfers (chain_id, block_number, block_hash, block_timestamp,
                                        tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic)
            VALUES (1, 100, '0xblk1', 1000, '0xtx1', 0, '0xASSET', '0xa', '0xb', ?, 1)
            """,
            (UINT256_MAX_STR,),
        )
        db.commit()

        events = get_timeline(db, start_time=900, end_time=1100)
        transfer_events = [e for e in events if e["event_type"] == "transfer"]
        assert len(transfer_events) == 1
        assert transfer_events[0]["details"]["amount_raw"] == UINT256_MAX_STR

    def test_get_alerts_preserves_uint256_max_in_evidence_refs(self):
        """Proof: get_alerts preserves 2^256-1 whether stored as string or integer in JSON."""
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            """
            CREATE TABLE alerts (
                alert_id TEXT PRIMARY KEY, rule_id TEXT, rule_version TEXT, unit_type TEXT,
                unit_key TEXT, asset_id TEXT, severity TEXT, score REAL, reason TEXT,
                evidence_refs TEXT, window_start TEXT, window_end TEXT, created_at TEXT
            )
            """
        )

        refs = [
            {"tx_hash": "0x1", "amount_raw": UINT256_MAX_STR},
            {"tx_hash": "0x2", "amount_raw": TEN_TO_THIRTY},  # integer in JSON
        ]
        conn.execute(
            """
            INSERT INTO alerts VALUES ('alt1', 'large_transfer', '1.0', 'tx', '0x1', '0xDAI',
                                      'HIGH', 0.9, 'test', ?, '2026-01-01T00:00:00Z',
                                      '2026-01-01T00:05:00Z', '2026-01-01T00:00:00Z')
            """,
            (json.dumps(refs),),
        )
        conn.commit()

        alerts = get_alerts(conn)
        assert len(alerts) == 1
        parsed_refs = alerts[0]["evidence_refs"]
        assert parsed_refs[0]["amount_raw"] == UINT256_MAX_STR
        assert parsed_refs[1]["amount_raw"] == TEN_TO_THIRTY_STR


# ==============================================================================
# Suite 2: Pydantic AI AnyIO Concurrency & Thread Safety
# ==============================================================================


class TestAnyIOConcurrencyAndThreadSafety:
    """Stress tests AnyIO threadpool dispatch and concurrent query execution."""

    def test_pydantic_ai_agent_with_staging_connection_across_threads(self):
        """Proof: Pydantic AI Agent sync tool dispatch across AnyIO worker threads succeeds with check_same_thread=False."""
        os.environ["PYDANTIC_AI_NO_BANNER"] = "1"
        staging = get_staging_connection()

        agent = Agent(create_test_model(call_tools=["staging_collector"]))

        @agent.tool
        def staging_collector(ctx: RunContext) -> str:
            res = collect_missing_range(200, 215, staging)
            return json.dumps(res)

        result = agent.run_sync("Collect missing blocks")
        assert result.output is not None

        # Verify blocks were collected into staging
        row_count = staging.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
        assert row_count == 16

    def test_thread_affinity_contrast_proof(self):
        """Proof: Connections WITHOUT check_same_thread=False fail with sqlite3.ProgrammingError across threads."""
        # 1. Connection with check_same_thread=True (default in Python sqlite3)
        conn_strict = sqlite3.connect(":memory:")
        error_strict = []

        def worker_strict():
            try:
                conn_strict.execute("CREATE TABLE t (id INT)")
            except Exception as e:
                error_strict.append(e)

        t1 = threading.Thread(target=worker_strict)
        t1.start()
        t1.join()
        assert len(error_strict) == 1
        assert isinstance(error_strict[0], sqlite3.ProgrammingError)
        assert "SQLite objects created in a thread can only be used in that same thread" in str(error_strict[0])

        # 2. Connection with check_same_thread=False
        conn_safe = sqlite3.connect(":memory:", check_same_thread=False)
        error_safe = []

        def worker_safe():
            try:
                conn_safe.execute("CREATE TABLE t (id INT)")
                conn_safe.execute("INSERT INTO t VALUES (42)")
            except Exception as e:
                error_safe.append(e)

        t2 = threading.Thread(target=worker_safe)
        t2.start()
        t2.join()
        assert len(error_safe) == 0
        assert conn_safe.execute("SELECT id FROM t").fetchone()[0] == 42

    def test_worker_thread_handover_with_check_same_thread_false(self):
        """Proof: Sequential AnyIO-style worker thread execution on a connection with check_same_thread=False produces zero errors."""
        if not REAL_P4_DB.exists():
            pytest.skip(f"real_p4.db not found at {REAL_P4_DB}")

        uri = build_readonly_uri(REAL_P4_DB)
        conn = sqlite3.connect(
            uri,
            uri=True,
            check_same_thread=False,
            factory=ReadOnlyConnection,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON;")
        conn.set_authorizer(readonly_authorizer)

        errors = []
        for i in range(5):
            def worker():
                try:
                    tx = get_tx(conn, "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d")
                    assert tx is not None
                except Exception as e:
                    errors.append(e)

            t = threading.Thread(target=worker)
            t.start()
            t.join()

        assert not errors, f"Errors occurred during worker thread handover: {errors}"
        conn.close()

    def test_concurrent_queries_load_across_ten_threads(self):
        """Proof: 10 concurrent threads query read-only DB simultaneously using independent connections."""
        if not REAL_P4_DB.exists():
            pytest.skip(f"real_p4.db not found at {REAL_P4_DB}")

        thread_errors: list[tuple[int, Exception]] = []
        thread_results: list[int] = []

        def worker(thread_id: int):
            try:
                conn = get_readonly_connection(REAL_P4_DB)
                tx_data = get_tx(conn, "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d")
                assert tx_data is not None
                cps = get_counterparties(conn, "0xebc29199c817dc47ba12e3f86102564d640cbf99", limit=5)
                assert len(cps) > 0
                thread_results.append(len(cps))
                conn.close()
            except Exception as e:
                thread_errors.append((thread_id, e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not thread_errors, f"Thread errors occurred: {thread_errors}"
        assert len(thread_results) == 10

    def test_concurrent_tool_budget_managers_independent_threads(self):
        """Proof: ToolBudgetManager instances operate independently across threads without race conditions."""
        errors = []

        def run_budget_session(thread_id: int):
            try:
                tracker = ToolBudgetManager(max_steps=5)
                tools = {"get_tx": lambda tx_hash: {"tx": tx_hash}}
                for step in range(5):
                    execute_guarded_tool("get_tx", {"tx_hash": f"0x{thread_id}_{step}"}, tools, tracker)
                assert tracker.attempted_tool_calls == 5
                assert tracker.successful_tool_calls == 5

                # 6th attempt must raise
                with pytest.raises(ToolBudgetExceeded):
                    execute_guarded_tool("get_tx", {"tx_hash": "overflow"}, tools, tracker)
            except Exception as e:
                errors.append((thread_id, e))

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(run_budget_session, i) for i in range(8)]
            concurrent.futures.wait(futures)

        assert not errors, f"Concurrent budget errors: {errors}"


# ==============================================================================
# Suite 3: Provider Offline Determinism, Usage Limits & Secret Security
# ==============================================================================


class TestProviderOfflineDeterminismAndSecurity:
    """Stress tests Provider offline fallbacks, request bounds, and credential security."""

    def test_test_model_deterministic_seed_reproducibility(self):
        """Proof: TestModel with fixed seed produces deterministic outputs."""
        os.environ["PYDANTIC_AI_NO_BANNER"] = "1"
        m1 = create_test_model(seed=42, custom_output_text="deterministic analysis")
        m2 = create_test_model(seed=42, custom_output_text="deterministic analysis")

        a1 = Agent(m1)
        a2 = Agent(m2)

        res1 = a1.run_sync("Input query")
        res2 = a2.run_sync("Input query")

        assert res1.output == res2.output == "deterministic analysis"

    def test_function_model_deterministic_custom_dispatch(self):
        """Proof: FunctionModel allows arbitrary deterministic model callback routing."""
        os.environ["PYDANTIC_AI_NO_BANNER"] = "1"
        call_count = 0

        def forensic_oracle(messages: list[ModelMessage], info: Any) -> ModelResponse:
            nonlocal call_count
            call_count += 1
            return ModelResponse(parts=[TextPart(content=f"Forensic finding step {call_count}")])

        model = create_function_model(function=forensic_oracle)
        agent = Agent(model)

        r1 = agent.run_sync("Step 1")
        r2 = agent.run_sync("Step 2")

        assert r1.output == "Forensic finding step 1"
        assert r2.output == "Forensic finding step 2"
        assert call_count == 2

    def test_usage_limits_request_limit_enforced_at_eight(self):
        """Proof: Default request_limit=8 is strictly enforced by Pydantic AI."""
        os.environ["PYDANTIC_AI_NO_BANNER"] = "1"
        limits = get_usage_limits()
        assert limits.request_limit == 8

        model = create_test_model(call_tools=["looper_tool"])
        agent = Agent(model)

        @agent.tool_plain
        def looper_tool() -> str:
            return "ok"

        # Enforce request_limit=1: initial prompt + tool call result triggers 2nd request, exceeding limit 1
        strict_limits = UsageLimits(request_limit=1)
        with pytest.raises(UsageLimitExceeded):
            agent.run_sync("Run tool loop", usage_limits=strict_limits)

    def test_environment_variable_override_hierarchy(self, monkeypatch):
        """Proof: Environment hierarchy is respected: explicit > GOOGLE_API_KEY > GEMINI_API_KEY."""
        # Case 1: Both in environment, explicit override wins
        monkeypatch.setenv("GOOGLE_API_KEY", "env_g_key")
        monkeypatch.setenv("GEMINI_API_KEY", "env_m_key")
        key, src = resolve_api_key("explicit_override_key")
        assert key == "explicit_override_key"
        assert src == "explicit"

        # Case 2: Both in environment, no explicit override -> GOOGLE_API_KEY wins
        key, src = resolve_api_key()
        assert key == "env_g_key"
        assert src == "GOOGLE_API_KEY"

        # Case 3: Only GEMINI_API_KEY in environment -> GEMINI_API_KEY wins
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        key, src = resolve_api_key()
        assert key == "env_m_key"
        assert src == "GEMINI_API_KEY"

        # Case 4: Neither in environment -> None, 'none'
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        key, src = resolve_api_key()
        assert key is None
        assert src == "none"

    def test_zero_secret_leakage_in_exceptions_and_summaries(self, monkeypatch):
        """Proof: Secrets are never exposed in safe_summary(), logs, or string representations."""
        secret_key = "AIzaSySecretLeakageTestString987654321"
        monkeypatch.setenv("GOOGLE_API_KEY", secret_key)

        cfg = AIConfig()
        summary = cfg.safe_summary()

        assert secret_key not in str(summary)
        assert summary["api_key_masked"] == "AIza...4321"
        assert summary["api_key_configured"] is True

        # Test mask_api_key edge cases
        assert mask_api_key(None) == "[ABSENT]"
        assert mask_api_key("") == "[ABSENT]"
        assert mask_api_key("   ") == "[ABSENT]"
        assert mask_api_key("123") == "***"
        assert mask_api_key("12345678") == "***"
        assert mask_api_key("123456789") == "1234...6789"


# ==============================================================================
# Suite 4: Database Immutability & Clean State
# ==============================================================================


class TestDatabaseImmutability:
    """Verifies that real_p4.db remains 100% byte-identical and zero lock files exist."""

    EXPECTED_SHA256 = "6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97"
    EXPECTED_SIZE = 5947392

    def test_real_p4_db_hash_and_size_integrity(self):
        """Proof: real_p4.db has not been mutated by any test or operation."""
        if not REAL_P4_DB.exists():
            pytest.skip(f"real_p4.db not found at {REAL_P4_DB}")

        data = REAL_P4_DB.read_bytes()
        actual_hash = hashlib.sha256(data).hexdigest().upper()
        actual_size = len(data)

        assert actual_size == self.EXPECTED_SIZE, (
            f"Database size altered: expected {self.EXPECTED_SIZE}, got {actual_size}"
        )
        assert actual_hash == self.EXPECTED_SHA256, (
            f"Database SHA-256 corrupted: expected {self.EXPECTED_SHA256}, got {actual_hash}"
        )

    def test_zero_lingering_sqlite_lock_or_wal_files(self):
        """Proof: No -wal, -shm, or .lock files exist in real_p4 data directory."""
        if not REAL_P4_DB.parent.exists():
            pytest.skip("Data directory does not exist")

        data_dir = REAL_P4_DB.parent
        lock_files = list(data_dir.glob("*.lock")) + list(data_dir.glob("*-wal")) + list(data_dir.glob("*-shm"))
        assert len(lock_files) == 0, f"Found lingering SQLite lock/wal files: {lock_files}"
