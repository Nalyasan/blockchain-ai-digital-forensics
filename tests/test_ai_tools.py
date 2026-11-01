"""Unit Test Suite for Milestone 2 Forensics Tools, Staging, and Guardrails.

Verifies:
- Block range validation: <= 20 blocks, RangeLimitExceeded on 21+, ValueError on invalid/negative
- Isolated staging collection: writes only to staging DB, never canonical DB
- Session call limit: max 2 calls per session, SessionLimitExceeded on 3rd call
- Tool guardrails & step budget: MAX_AI_TOOL_STEPS = 5, UnauthorizedToolError on unauthorized
- 5 read-only queries on real_p4.db: exact integer string amount_raw, no float truncation
- Thread safety with check_same_thread=False
- G5-02 invariant: zero forbidden mutating statements
"""

import ast
import json
import sqlite3
import threading
from pathlib import Path
import pytest

from forensics.ai.db_readonly import get_readonly_connection
from forensics.ai.tools import (
    AUTHORIZED_TOOLS,
    MAX_AI_TOOL_STEPS,
    MAX_BLOCKS_PER_COLLECT,
    MAX_COLLECT_CALLS_PER_SESSION,
    ProductionDatabaseMutationError,
    RangeLimitExceeded,
    RULE_ALIASES,
    SessionLimitExceeded,
    ToolBudgetExceeded,
    ToolBudgetManager,
    ToolCallBudgetTracker,
    UnauthorizedToolError,
    collect_missing_range,
    execute_guarded_tool,
    execute_tool_with_guardrails,
    get_address_history,
    get_alerts,
    get_counterparties,
    get_staging_connection,
    get_timeline,
    get_tx,
    init_staging_tables,
    validate_block_range,
    verify_staging_database,
)

REAL_P4_DB = Path(r"D:\Projest\worktrees\p4_real_integration\data\real_p4.db")


class TestBlockRangeValidation:
    """Verifies block range boundary conditions."""

    def test_single_block_allowed(self):
        assert validate_block_range(100, 100) == 1

    def test_twenty_blocks_allowed(self):
        assert validate_block_range(100, 119) == 20

    def test_twenty_one_blocks_raises_range_limit_exceeded(self):
        with pytest.raises(RangeLimitExceeded, match="Range limit exceeded"):
            validate_block_range(100, 120)

    def test_range_limit_exceeded_is_subclass_of_value_error(self):
        with pytest.raises(ValueError):
            validate_block_range(0, 20)  # 21 blocks

    def test_inverted_range_raises_value_error(self):
        with pytest.raises(ValueError, match="start_block .* must be <= end_block"):
            validate_block_range(105, 100)

    def test_negative_block_raises_value_error(self):
        with pytest.raises(ValueError, match="non-negative"):
            validate_block_range(-1, 10)
        with pytest.raises(ValueError, match="non-negative"):
            validate_block_range(10, -5)

    def test_non_integer_type_raises_type_error(self):
        with pytest.raises(TypeError, match="must be integers"):
            validate_block_range("100", 110)
        with pytest.raises(TypeError, match="must be integers"):
            validate_block_range(True, 10)
        with pytest.raises(TypeError, match="must be integers"):
            validate_block_range(10.5, 20)


class TestStagingDatabaseIsolation:
    """Verifies isolation of staging database and protection of canonical evidence."""

    def test_collect_writes_to_isolated_memory_staging(self):
        staging = get_staging_connection()
        tracker = ToolBudgetManager()
        res = collect_missing_range(100, 119, staging, tracker=tracker)

        assert res["status"] == "success"
        assert res["blocks_count"] == 20
        assert tracker.collect_calls == 1

        blocks_count = staging.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
        assert blocks_count == 20

        # Check status is 'staging'
        statuses = [row[0] for row in staging.execute("SELECT status FROM blocks").fetchall()]
        assert all(s == "staging" for s in statuses)

        c_runs = staging.execute("SELECT mode, status FROM collector_runs").fetchall()
        assert len(c_runs) == 1
        assert c_runs[0][0] == "ai_tool"
        assert c_runs[0][1] == "success"

        audit_rows = staging.execute("SELECT action FROM audit_events").fetchall()
        assert len(audit_rows) == 1
        assert audit_rows[0][0] == "AI_COLLECT_RANGE"

    def test_refuse_to_collect_into_canonical_db(self):
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not available")
        ro_conn = get_readonly_connection(REAL_P4_DB)
        with pytest.raises(ProductionDatabaseMutationError):
            collect_missing_range(100, 110, ro_conn)

    def test_refuse_to_collect_into_db_with_canonical_name(self, tmp_path):
        fake_canonical = tmp_path / "real_p4.db"
        conn = sqlite3.connect(fake_canonical)
        with pytest.raises(ProductionDatabaseMutationError, match="Refusing to write"):
            collect_missing_range(100, 110, conn)
        conn.close()


class TestSessionCallLimit:
    """Verifies at most 2 collect invocations per session."""

    def test_session_limit_strictly_enforced_at_two(self):
        staging = get_staging_connection()
        tracker = ToolBudgetManager()

        collect_missing_range(10, 15, staging, tracker=tracker)
        assert tracker.collect_calls == 1

        collect_missing_range(16, 20, staging, tracker=tracker)
        assert tracker.collect_calls == 2

        with pytest.raises(SessionLimitExceeded, match="Session call limit exceeded"):
            collect_missing_range(21, 25, staging, tracker=tracker)

        assert tracker.collect_calls == 2


class TestToolGuardrailsAndStepBudget:
    """Verifies tool whitelisting, MAX_AI_TOOL_STEPS = 5, and structured logging."""

    def test_authorized_tools_exact_members(self):
        expected = {
            "get_alerts",
            "get_tx",
            "get_address_history",
            "get_counterparties",
            "get_timeline",
            "collect_missing_range",
        }
        assert AUTHORIZED_TOOLS == expected

    def test_unauthorized_tools_rejected(self):
        tracker = ToolBudgetManager()
        tools = {"get_tx": lambda tx_hash: {"tx": tx_hash}}

        for bad_tool in ["bash", "read_file", "eval", "python", "mcp_search"]:
            with pytest.raises(UnauthorizedToolError, match="is not authorized"):
                execute_guarded_tool(bad_tool, {"arg": "val"}, tools, tracker)

        assert tracker.attempted_tool_calls == 5
        assert tracker.failed_tool_calls == 5
        assert tracker.successful_tool_calls == 0

    def test_max_ai_tool_steps_enforced_on_sixth_attempt(self):
        tracker = ToolBudgetManager(max_steps=5)
        tools = {"get_tx": lambda tx_hash: {"tx": tx_hash}}

        for i in range(5):
            execute_guarded_tool("get_tx", {"tx_hash": f"0x{i}"}, tools, tracker)

        assert tracker.attempted_tool_calls == 5
        assert tracker.successful_tool_calls == 5

        with pytest.raises(ToolBudgetExceeded, match="Tool execution budget exhausted"):
            execute_guarded_tool("get_tx", {"tx_hash": "0x5"}, tools, tracker)

    def test_failed_attempts_consume_budget_step(self):
        tracker = ToolBudgetManager(max_steps=5)
        tools = {
            "get_tx": lambda tx_hash: {"tx": tx_hash},
            "collect_missing_range": lambda: None,
        }

        # Step 1: unauthorized tool
        with pytest.raises(UnauthorizedToolError):
            execute_guarded_tool("bash", {}, tools, tracker)

        # Step 2: successful call
        execute_guarded_tool("get_tx", {"tx_hash": "0x1"}, tools, tracker)

        # Step 3: unauthorized tool
        with pytest.raises(UnauthorizedToolError):
            execute_guarded_tool("cmd_exec", {}, tools, tracker)

        # Step 4: successful call
        execute_guarded_tool("get_tx", {"tx_hash": "0x2"}, tools, tracker)

        # Step 5: successful call
        execute_guarded_tool("get_tx", {"tx_hash": "0x3"}, tools, tracker)

        assert tracker.attempted_tool_calls == 5
        assert tracker.successful_tool_calls == 3
        assert tracker.failed_tool_calls == 2

        # Step 6: budget exhausted
        with pytest.raises(ToolBudgetExceeded):
            execute_guarded_tool("get_tx", {"tx_hash": "0x4"}, tools, tracker)

    def test_tool_calls_log_json_serialization(self):
        tracker = ToolBudgetManager(max_steps=5)
        tools = {"get_tx": lambda tx_hash: {"tx": tx_hash}}

        execute_guarded_tool("get_tx", {"tx_hash": "0xabc"}, tools, tracker)

        log_json = tracker.to_tool_calls_log()
        data = json.loads(log_json)

        assert "summary" in data
        assert "calls" in data
        assert data["summary"]["attempted_steps"] == 1
        assert data["summary"]["successful_steps"] == 1
        assert data["summary"]["failed_steps"] == 0
        assert data["summary"]["budget_exhausted"] is False
        assert len(data["calls"]) == 1
        assert data["calls"][0]["tool_name"] == "get_tx"
        assert data["calls"][0]["status"] == "success"


@pytest.fixture(scope="module")
def real_db():
    if not REAL_P4_DB.exists():
        pytest.skip(f"real_p4.db not found at {REAL_P4_DB}")
    conn = get_readonly_connection(REAL_P4_DB)
    yield conn
    conn.close()


class TestReadOnlyToolsOnRealDB:
    """Verifies all five read-only tools against verified real_p4.db."""

    def test_get_alerts_basic_and_filters(self, real_db):
        alerts = get_alerts(real_db, limit=10)
        assert len(alerts) == 10
        for a in alerts:
            assert "alert_id" in a
            assert "rule_id" in a
            assert isinstance(a["evidence_refs"], list)

        # Test canonical rule filtering
        r1_alerts = get_alerts(real_db, rule_id="large_transfer", limit=100)
        assert len(r1_alerts) > 0
        assert all(a["rule_id"] == "large_transfer" for a in r1_alerts)

        # Test alias filtering ('r1' -> 'large_transfer')
        alias_alerts = get_alerts(real_db, rule_id="r1", limit=100)
        assert len(alias_alerts) == len(r1_alerts)

        # Test severity filtering
        high_alerts = get_alerts(real_db, severity="HIGH", limit=100)
        assert len(high_alerts) > 0
        assert all(a["severity"] == "HIGH" for a in high_alerts)

        # Test empty result for non-existent rule
        empty = get_alerts(real_db, rule_id="non_existent_rule")
        assert empty == []

    def test_get_alerts_exact_amount_raw_in_evidence_refs(self, real_db):
        alerts = get_alerts(real_db, limit=50)
        found_amount = False
        for a in alerts:
            for ref in a.get("evidence_refs", []):
                if isinstance(ref, dict) and "amount_raw" in ref and ref["amount_raw"] is not None:
                    found_amount = True
                    assert isinstance(ref["amount_raw"], str)
                    assert ref["amount_raw"].isdigit()
        assert found_amount

    def test_get_tx_euler_exploit(self, real_db):
        euler_exploit_tx = "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d"
        tx_data = get_tx(real_db, euler_exploit_tx)
        assert tx_data is not None
        assert tx_data["tx_hash"].lower() == euler_exploit_tx.lower()
        assert "transfers" in tx_data
        assert len(tx_data["transfers"]) > 0

        # Case-insensitivity check
        tx_data_upper = get_tx(real_db, euler_exploit_tx.upper())
        assert tx_data_upper is not None
        assert tx_data_upper["tx_hash"].lower() == euler_exploit_tx.lower()

        # Non-existent transaction returns None
        assert get_tx(real_db, "0xdeadbeef99999999999999999999999999999999999999999999999999999999") is None

    def test_get_tx_synthetic_from_transfers(self, real_db):
        cursor = real_db.cursor()
        cursor.execute(
            """
            SELECT tx_hash FROM asset_transfers
            WHERE tx_hash NOT IN (SELECT tx_hash FROM transactions)
            LIMIT 1
            """
        )
        row = cursor.fetchone()
        if row:
            tx_h = row[0]
            tx_data = get_tx(real_db, tx_h)
            assert tx_data is not None
            assert tx_data["tx_hash"] == tx_h
            assert len(tx_data["transfers"]) > 0

    def test_get_address_history_euler(self, real_db):
        euler_contract = "0xebc29199c817dc47ba12e3f86102564d640cbf99"
        history = get_address_history(real_db, euler_contract, limit=50)
        assert len(history) > 0
        for t in history:
            assert isinstance(t["amount_raw"], str)
            addr_match = (
                (t["from_addr"] or "").lower() == euler_contract.lower()
                or (t["to_addr"] or "").lower() == euler_contract.lower()
            )
            assert addr_match

        # Check sorting: block_number ASC, log_index ASC
        for i in range(len(history) - 1):
            curr = history[i]
            nxt = history[i + 1]
            assert (curr["block_number"], curr["log_index"]) <= (nxt["block_number"], nxt["log_index"])

    def test_get_counterparties_exact_integer_volumes(self, real_db):
        euler_contract = "0xebc29199c817dc47ba12e3f86102564d640cbf99"
        cps = get_counterparties(real_db, euler_contract, limit=50)
        assert len(cps) > 0
        for cp in cps:
            assert "counterparty" in cp
            assert "volume_sent_raw" in cp
            assert "volume_received_raw" in cp
            assert "total_volume_raw" in cp

            assert isinstance(cp["volume_sent_raw"], str)
            assert isinstance(cp["volume_received_raw"], str)
            assert isinstance(cp["total_volume_raw"], str)

            sent_int = int(cp["volume_sent_raw"])
            recv_int = int(cp["volume_received_raw"])
            total_int = int(cp["total_volume_raw"])
            assert total_int == sent_int + recv_int

    def test_get_timeline_euler_and_curve(self, real_db):
        euler_timeline = get_timeline(real_db, case_id="euler", limit=50)
        assert len(euler_timeline) > 0
        types_present = {ev["event_type"] for ev in euler_timeline}
        assert "transfer" in types_present or "block" in types_present

        # Verify deterministic ordering: timestamp ASC, block_number ASC
        for i in range(len(euler_timeline) - 1):
            t_curr = euler_timeline[i]["timestamp"] or 0
            t_nxt = euler_timeline[i + 1]["timestamp"] or 0
            assert t_curr <= t_nxt

        curve_timeline = get_timeline(real_db, case_id="curve", limit=50)
        assert len(curve_timeline) > 0


class TestThreadSafetyAnyIOCompatibility:
    """Verifies that SQLite connections with check_same_thread=False execute in background threads."""

    def test_staging_connection_in_worker_thread(self):
        staging = get_staging_connection()
        error_holder = []

        def worker():
            try:
                res = collect_missing_range(50, 55, staging)
                assert res["blocks_count"] == 6
            except Exception as e:
                error_holder.append(e)

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()

        assert not error_holder, f"Worker thread raised exception: {error_holder}"


class TestForensicInvariantsG502:
    """Proof of G5-02 invariant in tools.py."""

    def test_zero_insert_or_replace_invariant(self):
        code_path = Path("forensics/ai/tools.py")
        content = code_path.read_text(encoding="utf-8").upper()
        assert "INSERT OR REPLACE" not in content, "Forbidden 'INSERT OR REPLACE' found"
        assert "REPLACE INTO" not in content, "Forbidden 'REPLACE INTO' found"
        assert "INSERT OR IGNORE" not in content, "Forbidden 'INSERT OR IGNORE' found"

    def test_ast_validity(self):
        code_path = Path("forensics/ai/tools.py")
        tree = ast.parse(code_path.read_text(encoding="utf-8"), filename="tools.py")
        assert isinstance(tree, ast.Module)
