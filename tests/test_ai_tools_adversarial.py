"""Adversarial Challenge Test Suite for Milestone 2: Forensics Tools, Budgets & Staging.

Authored by Milestone 2 Adversarial Challenger 1.
Adversarially probes:
1. Unauthorized tool calls (system_shell, sh, bash, filesystem_read, eval, web_search, case/whitespace evasion)
2. ToolBudgetManager step budgeting (failed attempts count toward MAX_AI_TOOL_STEPS = 5, call #6 blocked)
3. Block range boundaries (1, 20 valid; 21, 22, 100 RangeLimitExceeded; inverted/negative ValueError; types)
4. Staging database isolation and zero canonical DB mutation (verifies SHA-256 of real_p4.db)
5. Session call limits on collect_missing_range (2 calls allowed, 3rd raises SessionLimitExceeded)
"""

import hashlib
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
    validate_block_range,
    verify_staging_database,
)
from forensics.paths import REAL_P4_DB as CANONICAL_REAL_P4_DB

REAL_P4_DB = CANONICAL_REAL_P4_DB if CANONICAL_REAL_P4_DB.exists() else Path(r"D:\Projest\worktrees\p4_real_integration\data\real_p4.db")
EXPECTED_REAL_P4_SHA256 = "6bd9aed48ac2742d0862198bff65994861244ec681dc8abeb3e6f771e7808c97"
EXPECTED_REAL_P4_SIZE = 5947392


def compute_sha256(path: Path) -> str:
    """Computes SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class TestAdversarialUnauthorizedTools:
    """Challenge 1: Unauthorized tool invocations must be strictly rejected."""

    @pytest.mark.parametrize(
        "unauthorized_tool",
        [
            # Required test cases from orchestrator
            "system_shell",
            "sh",
            "bash",
            "filesystem_read",
            "eval",
            "web_search",
            # Additional shell and injection vectors
            "exec",
            "system",
            "cmd.exe",
            "powershell",
            "subprocess",
            "python",
            "__import__",
            "open",
            # Filesystem exploration vectors
            "read_file",
            "write_file",
            "list_dir",
            "delete_file",
            # Unrestricted network / external vectors
            "fetch_url",
            "mcp_search",
            "curl",
            "wget",
            # Case tampering attacks (whitelist is case-sensitive)
            "GET_TX",
            "Get_Tx",
            "GET_ALERTS",
            "Get_Alerts",
            "COLLECT_MISSING_RANGE",
            "Collect_Missing_Range",
            "GET_TIMELINE",
            # Whitespace and formatting evasion attacks
            " get_tx",
            "get_tx ",
            " get_tx ",
            "get_alerts\n",
            "get_tx\x00",
            "get_tx; rm -rf",
            "",
            "   ",
        ],
    )
    def test_unauthorized_tools_raise_unauthorized_tool_error(self, unauthorized_tool):
        tracker = ToolBudgetManager()
        tools = {"get_tx": lambda tx_hash: {"tx": tx_hash}}

        with pytest.raises(UnauthorizedToolError) as exc_info:
            execute_guarded_tool(unauthorized_tool, {}, tools, tracker)

        # Must be an instance of PermissionError
        assert isinstance(exc_info.value, PermissionError)
        assert "not authorized" in str(exc_info.value)
        # Attempt must have been recorded
        assert tracker.attempted_tool_calls == 1
        assert tracker.failed_tool_calls == 1
        assert tracker.successful_tool_calls == 0


class TestAdversarialToolBudgetManager:
    """Challenge 2: ToolBudgetManager step budgeting under adversarial conditions."""

    def test_five_unauthorized_attempts_consume_full_budget_call_six_blocked(self):
        tracker = ToolBudgetManager(max_steps=5)
        tools = {"get_tx": lambda tx_hash: {"tx": tx_hash}}
        bad_tools = ["system_shell", "sh", "bash", "filesystem_read", "eval"]

        for i, bad_tool in enumerate(bad_tools, start=1):
            with pytest.raises(UnauthorizedToolError):
                execute_guarded_tool(bad_tool, {}, tools, tracker)
            assert tracker.attempted_tool_calls == i
            assert tracker.failed_tool_calls == i
            assert tracker.successful_tool_calls == 0

        assert tracker.attempted_tool_calls == 5

        # Call #6 must immediately raise ToolBudgetExceeded
        with pytest.raises(ToolBudgetExceeded, match="Tool execution budget exhausted"):
            execute_guarded_tool("web_search", {}, tools, tracker)

        # Call #6 even with a valid tool must also raise ToolBudgetExceeded
        with pytest.raises(ToolBudgetExceeded, match="Tool execution budget exhausted"):
            execute_guarded_tool("get_tx", {"tx_hash": "0x123"}, tools, tracker)

    def test_interleaved_valid_and_invalid_calls_budget_enforcement(self):
        tracker = ToolBudgetManager(max_steps=5)
        tools = {"get_tx": lambda tx_hash: {"tx": tx_hash}}

        # Call 1: Valid
        res1 = execute_guarded_tool("get_tx", {"tx_hash": "0x1"}, tools, tracker)
        assert res1 == {"tx": "0x1"}
        assert tracker.attempted_tool_calls == 1
        assert tracker.successful_tool_calls == 1
        assert tracker.failed_tool_calls == 0

        # Call 2: Invalid (Unauthorized)
        with pytest.raises(UnauthorizedToolError):
            execute_guarded_tool("bash", {}, tools, tracker)
        assert tracker.attempted_tool_calls == 2
        assert tracker.successful_tool_calls == 1
        assert tracker.failed_tool_calls == 1

        # Call 3: Valid
        res3 = execute_guarded_tool("get_tx", {"tx_hash": "0x3"}, tools, tracker)
        assert res3 == {"tx": "0x3"}
        assert tracker.attempted_tool_calls == 3
        assert tracker.successful_tool_calls == 2
        assert tracker.failed_tool_calls == 1

        # Call 4: Invalid (Unauthorized)
        with pytest.raises(UnauthorizedToolError):
            execute_guarded_tool("system_shell", {}, tools, tracker)
        assert tracker.attempted_tool_calls == 4
        assert tracker.successful_tool_calls == 2
        assert tracker.failed_tool_calls == 2

        # Call 5: Valid
        res5 = execute_guarded_tool("get_tx", {"tx_hash": "0x5"}, tools, tracker)
        assert res5 == {"tx": "0x5"}
        assert tracker.attempted_tool_calls == 5
        assert tracker.successful_tool_calls == 3
        assert tracker.failed_tool_calls == 2

        # Call 6: Blocked by budget ceiling
        with pytest.raises(ToolBudgetExceeded, match="Tool execution budget exhausted"):
            execute_guarded_tool("get_tx", {"tx_hash": "0x6"}, tools, tracker)

        # Call 7: Still blocked
        with pytest.raises(ToolBudgetExceeded, match="Tool execution budget exhausted"):
            execute_guarded_tool("get_tx", {"tx_hash": "0x7"}, tools, tracker)

    def test_internal_tool_exception_consumes_step_and_blocks_at_step_six(self):
        tracker = ToolBudgetManager(max_steps=5)

        def faulty_tx(tx_hash: str):
            if tx_hash == "faulty":
                raise ValueError("Simulated internal query failure")
            return {"tx": tx_hash}

        tools = {"get_tx": faulty_tx}

        # Step 1: Valid
        execute_guarded_tool("get_tx", {"tx_hash": "0x1"}, tools, tracker)
        # Step 2: Valid
        execute_guarded_tool("get_tx", {"tx_hash": "0x2"}, tools, tracker)
        # Step 3: Tool internal failure
        with pytest.raises(ValueError, match="Simulated internal query failure"):
            execute_guarded_tool("get_tx", {"tx_hash": "faulty"}, tools, tracker)
        assert tracker.attempted_tool_calls == 3
        assert tracker.successful_tool_calls == 2
        assert tracker.failed_tool_calls == 1

        # Step 4: Valid
        execute_guarded_tool("get_tx", {"tx_hash": "0x4"}, tools, tracker)
        # Step 5: Valid
        execute_guarded_tool("get_tx", {"tx_hash": "0x5"}, tools, tracker)

        assert tracker.attempted_tool_calls == 5
        assert tracker.successful_tool_calls == 4
        assert tracker.failed_tool_calls == 1

        # Step 6: Blocked
        with pytest.raises(ToolBudgetExceeded):
            execute_guarded_tool("get_tx", {"tx_hash": "0x6"}, tools, tracker)

    def test_audit_log_json_integrity_after_mixed_calls(self):
        tracker = ToolBudgetManager(max_steps=5)
        tools = {"get_tx": lambda tx_hash: {"tx": tx_hash}}

        # 3 successes, 2 failures
        execute_guarded_tool("get_tx", {"tx_hash": "0x1"}, tools, tracker)
        with pytest.raises(UnauthorizedToolError):
            execute_guarded_tool("sh", {}, tools, tracker)
        execute_guarded_tool("get_tx", {"tx_hash": "0x2"}, tools, tracker)
        with pytest.raises(UnauthorizedToolError):
            execute_guarded_tool("filesystem_read", {}, tools, tracker)
        execute_guarded_tool("get_tx", {"tx_hash": "0x3"}, tools, tracker)

        # Trigger budget exceeded attempt
        with pytest.raises(ToolBudgetExceeded):
            execute_guarded_tool("get_tx", {"tx_hash": "0x4"}, tools, tracker)

        log_json = tracker.to_tool_calls_log()
        data = json.loads(log_json)

        assert data["summary"]["max_steps"] == 5
        assert data["summary"]["attempted_steps"] == 5
        assert data["summary"]["successful_steps"] == 3
        assert data["summary"]["failed_steps"] == 2
        assert data["summary"]["budget_exhausted"] is True

        # Total calls logged includes the 5 executed steps + 1 budget_exceeded step
        calls = data["calls"]
        assert len(calls) == 6
        assert calls[0]["status"] == "success"
        assert calls[1]["status"] == "unauthorized"
        assert calls[2]["status"] == "success"
        assert calls[3]["status"] == "unauthorized"
        assert calls[4]["status"] == "success"
        assert calls[5]["status"] == "budget_exceeded"


class TestAdversarialBlockRangeBoundaries:
    """Challenge 3: Block range boundaries, inverted ranges, and negative block numbers."""

    @pytest.mark.parametrize(
        "start, end, expected_count",
        [
            (0, 0, 1),
            (100, 100, 1),
            (16817990, 16817990, 1),
            (0, 19, 20),
            (100, 119, 20),
            (16817990, 16818009, 20),
            (10**12, 10**12 + 19, 20),  # large block numbers
        ],
    )
    def test_valid_boundary_sizes_succeed(self, start, end, expected_count):
        assert validate_block_range(start, end) == expected_count

    @pytest.mark.parametrize(
        "start, end, requested_count",
        [
            (0, 20, 21),
            (100, 120, 21),
            (100, 121, 22),
            (0, 99, 100),
            (100, 199, 100),
            (1000, 2000, 1001),
            (10**12, 10**12 + 20, 21),
        ],
    )
    def test_range_exceeding_twenty_blocks_raises_range_limit_exceeded(self, start, end, requested_count):
        with pytest.raises(RangeLimitExceeded) as exc_info:
            validate_block_range(start, end)
        assert isinstance(exc_info.value, ValueError)
        assert f"requested {requested_count} blocks" in str(exc_info.value)
        assert "maximum allowed is 20" in str(exc_info.value)

    @pytest.mark.parametrize(
        "start, end",
        [
            (100, 99),
            (1, 0),
            (20, 0),
            (1000, 500),
            (16818110, 16817990),
        ],
    )
    def test_inverted_ranges_raise_value_error(self, start, end):
        with pytest.raises(ValueError) as exc_info:
            validate_block_range(start, end)
        assert "must be <= end_block" in str(exc_info.value)

    @pytest.mark.parametrize(
        "start, end",
        [
            (-1, 0),
            (-1, 10),
            (0, -1),
            (10, -5),
            (-10, -5),
            (-1, -1),
        ],
    )
    def test_negative_block_numbers_raise_value_error(self, start, end):
        with pytest.raises(ValueError) as exc_info:
            validate_block_range(start, end)
        assert "must be non-negative" in str(exc_info.value)

    @pytest.mark.parametrize(
        "start, end",
        [
            ("100", 110),
            (100, "110"),
            ("100", "110"),
            (True, 10),
            (0, False),
            (10.5, 20),
            (10, 20.0),
            (None, 10),
            (10, None),
            ([100], 110),
            (100, {"end": 110}),
        ],
    )
    def test_non_integer_types_raise_type_error(self, start, end):
        with pytest.raises(TypeError) as exc_info:
            validate_block_range(start, end)
        assert "must be integers" in str(exc_info.value)

    def test_collect_missing_range_propagates_range_limit_exceeded(self):
        staging = get_staging_connection()
        tracker = ToolBudgetManager()

        with pytest.raises(RangeLimitExceeded):
            collect_missing_range(100, 120, staging, tracker=tracker)

        # Verify no blocks were inserted
        count = staging.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
        assert count == 0
        # Verify collect_calls counter was not incremented
        assert tracker.collect_calls == 0


class TestAdversarialStagingIsolation:
    """Challenge 4: Staging database isolation and zero canonical DB mutation."""

    def test_refuse_to_collect_into_real_p4_db_and_verify_sha256(self):
        if not REAL_P4_DB.exists():
            pytest.skip(f"real_p4.db not found at {REAL_P4_DB}")

        # Measure baseline hash and size
        baseline_sha = compute_sha256(REAL_P4_DB)
        baseline_size = REAL_P4_DB.stat().st_size
        assert baseline_sha == EXPECTED_REAL_P4_SHA256
        assert baseline_size == EXPECTED_REAL_P4_SIZE

        # Attempt 1: Using get_readonly_connection
        ro_conn = get_readonly_connection(REAL_P4_DB)
        tracker = ToolBudgetManager()
        with pytest.raises(ProductionDatabaseMutationError) as exc_info:
            collect_missing_range(100, 110, ro_conn, tracker=tracker)
        assert isinstance(exc_info.value, PermissionError)
        ro_conn.close()

        # Attempt 2: Direct sqlite3.connect against REAL_P4_DB (bypassing get_readonly_connection)
        direct_conn = sqlite3.connect(str(REAL_P4_DB))
        with pytest.raises(ProductionDatabaseMutationError) as exc_info2:
            collect_missing_range(100, 110, direct_conn, tracker=tracker)
        assert "Refusing to write to protected production database" in str(exc_info2.value)
        direct_conn.close()

        # Verify 100% bitwise immutability
        after_sha = compute_sha256(REAL_P4_DB)
        after_size = REAL_P4_DB.stat().st_size
        assert after_sha == baseline_sha, "CRITICAL: real_p4.db SHA-256 hash changed after mutation attempt!"
        assert after_size == baseline_size, "CRITICAL: real_p4.db byte size changed after mutation attempt!"

    def test_refuse_to_collect_into_canonical_name_pattern_db(self, tmp_path):
        for pattern_name in ["real_p4.db", "REAL_P4.DB", "canonical.db", "test_canonical_data.db"]:
            fake_db_path = tmp_path / pattern_name
            conn = sqlite3.connect(str(fake_db_path))
            with pytest.raises(ProductionDatabaseMutationError, match="Refusing to write"):
                verify_staging_database(conn)
            conn.close()

    def test_reject_non_sqlite_connection_objects(self):
        for invalid_target in [None, "sqlite3.db", 12345, {}, []]:
            with pytest.raises(TypeError, match="must be an sqlite3.Connection"):
                verify_staging_database(invalid_target)
            with pytest.raises(TypeError):
                collect_missing_range(1, 10, invalid_target)


class TestAdversarialSessionCallLimit:
    """Challenge 5: Session call limit strictly capped at MAX_COLLECT_CALLS_PER_SESSION (2)."""

    def test_session_limit_exceeded_on_third_call(self):
        staging = get_staging_connection()
        tracker = ToolBudgetManager(max_steps=5, max_collect_calls=2)

        # Call 1: Allowed (blocks 1..5)
        res1 = collect_missing_range(1, 5, staging, tracker=tracker)
        assert res1["status"] == "success"
        assert res1["session_collect_call_count"] == 1
        assert tracker.collect_calls == 1

        # Call 2: Allowed (blocks 6..10)
        res2 = collect_missing_range(6, 10, staging, tracker=tracker)
        assert res2["status"] == "success"
        assert res2["session_collect_call_count"] == 2
        assert tracker.collect_calls == 2

        # Call 3: Must raise SessionLimitExceeded
        with pytest.raises(SessionLimitExceeded) as exc_info:
            collect_missing_range(11, 15, staging, tracker=tracker)
        assert "Session call limit exceeded" in str(exc_info.value)
        assert "at most 2 times per session" in str(exc_info.value)

        # Call 4: Still raises SessionLimitExceeded
        with pytest.raises(SessionLimitExceeded):
            collect_missing_range(16, 20, staging, tracker=tracker)

        # Verify tracker state is strictly preserved
        assert tracker.collect_calls == 2

        # Verify only the first 10 blocks (from Call 1 and Call 2) exist in staging
        block_numbers = [row[0] for row in staging.execute("SELECT number FROM blocks ORDER BY number ASC").fetchall()]
        assert block_numbers == list(range(1, 11))
        assert 11 not in block_numbers
        assert 16 not in block_numbers

    def test_session_limit_exceeded_prevents_db_write(self):
        staging = get_staging_connection()
        tracker = ToolBudgetManager(max_steps=5, max_collect_calls=2)

        collect_missing_range(100, 105, staging, tracker=tracker)
        collect_missing_range(106, 110, staging, tracker=tracker)
        assert tracker.collect_calls == 2

        # Attempt call #3
        with pytest.raises(SessionLimitExceeded):
            collect_missing_range(111, 115, staging, tracker=tracker)

        # Verify collector_runs table has exactly 2 entries, not 3
        run_count = staging.execute("SELECT COUNT(*) FROM collector_runs").fetchone()[0]
        assert run_count == 2

        # Verify audit_events table has exactly 2 entries, not 3
        audit_count = staging.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        assert audit_count == 2
