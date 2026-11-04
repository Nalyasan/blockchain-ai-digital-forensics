"""Real Ethereum Incident Investigation Suite for P5 AI Investigator (Phase 7 / Milestone 4).

Independently verifies and consumes the P4-08 real-data SQLite database (`real_p4.db`)
using strictly read-only access:
1. Artifact Provenance & Integrity Verification:
   - Verifies 7,032 canonical asset_transfers, 172 alerts, and 498 evidence references.
   - Records SHA-256 digest of `real_p4.db` before and after all investigation runs to
     prove 100% database immutability.
2. Case 1 — Euler Finance Incident Investigation:
   - Seed tx: 0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d (Block 16817996)
   - Demonstrates R1–R4 alert investigation, transaction retrieval, address history,
     counterparty analysis, chronological timeline reconstruction, and evidence-linked
     forensic JSON output verified by the Independent Reference Checker.
3. Case 2 — Curve / Alchemix Vyper Reentrancy Incident Investigation:
   - Seed tx: 0xb676d789bb8b66a08105c844a49c2bcffb400e5c1cfabd4bc30cca4bff3c9801 (Block 17806772)
   - Demonstrates internal ETH trace resolution, R1–R4 alert correlation, address/counterparty
     analysis, timeline reconstruction, and Reference Checker verification.
4. Isolated Staging Collection (`collect_missing_range`):
   - Demonstrates 20-block inclusive collection into isolated staging DB, 21-block rejection,
     and canonical DB protection.
5. CLI End-to-End Investigation Execution:
   - Verifies `python -m forensics.cli investigate` on real incident data.
6. Conditional Live Gemini Flash Smoke Test:
   - Executes only when `GOOGLE_API_KEY` or `GEMINI_API_KEY` is configured and authorized;
     otherwise explicitly skips as PENDING.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from forensics.ai.db_readonly import get_readonly_connection, readonly_connection
from forensics.ai.investigator import ForensicInvestigator
from forensics.ai.provider import AIConfig, create_test_model, resolve_api_key
from forensics.ai.ref_checker import check_investigation_output
from forensics.ai.tools import (
    RangeLimitExceeded,
    ToolBudgetManager,
    collect_missing_range,
    get_address_history,
    get_alerts,
    get_counterparties,
    get_staging_connection,
    get_timeline,
    get_tx,
)
from forensics.paths import REAL_P4_DB as CANONICAL_REAL_P4_DB

REAL_P4_DB_PATH = CANONICAL_REAL_P4_DB if CANONICAL_REAL_P4_DB.exists() else Path("D:/Projest/worktrees/p4_real_integration/data/real_p4.db")

# Euler Finance Canonical Constants
EULER_TX_HASH = "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d"
EULER_BLOCK = 16817996
EULER_FROM_ADDR = "0x028171bca77440897b824ca71d1c56cac55b68a3"
EULER_TO_ADDR = "0xebc29199c817dc47ba12e3f86102564d640cbf99"
EULER_ASSET_DAI = "0x6b175474e89094c44da98b954eedeac495271d0f"
EULER_AMOUNT_RAW = "30000000000000000000000000"
EULER_ALERT_ID = "1ba703a159d38ebf21b5c6d4123c7e5d3d8e75e000b3990dd41f983094b96b38"

# Curve / Alchemix Canonical Constants
CURVE_TX_HASH = "0xb676d789bb8b66a08105c844a49c2bcffb400e5c1cfabd4bc30cca4bff3c9801"
CURVE_BLOCK = 17806772
CURVE_FROM_ADDR = "0x30fb95794a2051abe30a67892b3a1fa73947aee5"
CURVE_TO_ADDR = "0xdce5d6b41c32f578f875efffc0d422c57a75d7d8"
CURVE_ASSET_NATIVE = "NATIVE"
CURVE_AMOUNT_RAW = "7258701569350004501158"
CURVE_ALERT_ID = "e6bbfab35ec6327ef77bcdd812b4722700cdf6372672da5837bf0ef0e9438729"


def _compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@pytest.fixture(scope="module")
def real_db_baseline_sha256():
    """Captures baseline SHA-256 of real_p4.db before any test runs and verifies after."""
    if not REAL_P4_DB_PATH.exists():
        pytest.skip(f"P4-08 real database not found at {REAL_P4_DB_PATH}")
    pre_hash = _compute_sha256(REAL_P4_DB_PATH)
    yield pre_hash
    post_hash = _compute_sha256(REAL_P4_DB_PATH)
    assert post_hash == pre_hash, (
        f"CRITICAL FORENSIC VIOLATION: real_p4.db was mutated! Pre={pre_hash}, Post={post_hash}"
    )


@pytest.fixture
def ro_real_db(real_db_baseline_sha256):
    """Yields a strictly read-only connection to real_p4.db."""
    with readonly_connection(REAL_P4_DB_PATH) as conn:
        yield conn


class TestP408ArtifactIndependentVerification:
    """Independently verifies P4-08 real-data database metrics before consumption."""

    def test_verify_p4_08_canonical_counts(self, ro_real_db):
        tx_count = ro_real_db.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        blk_count = ro_real_db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
        xfer_count = ro_real_db.execute("SELECT COUNT(*) FROM asset_transfers WHERE synthetic = 0").fetchone()[0]
        alert_count = ro_real_db.execute("SELECT COUNT(*) FROM alerts WHERE synthetic = 0").fetchone()[0]

        assert tx_count == 18, f"Expected 18 canonical transactions, got {tx_count}"
        assert blk_count == 1789, f"Expected 1,789 canonical blocks, got {blk_count}"
        assert xfer_count == 7032, f"Expected 7,032 canonical transfers, got {xfer_count}"
        assert alert_count == 172, f"Expected 172 canonical alerts, got {alert_count}"

        # Confirm no separate evidence_references table exists (refs are embedded in alerts.evidence_refs)
        tables = {
            r[0]
            for r in ro_real_db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "evidence_references" not in tables

        # Confirm actual rule IDs in alerts table
        rule_ids = {
            r[0]
            for r in ro_real_db.execute("SELECT DISTINCT rule_id FROM alerts").fetchall()
        }
        assert rule_ids == {"large_transfer", "high_frequency", "fan_in_out", "rapid_pass_through"}

        # Count evidence references embedded across all 172 alerts
        rows = ro_real_db.execute("SELECT evidence_refs FROM alerts WHERE synthetic = 0").fetchall()
        total_evidence_refs = 0
        for r in rows:
            refs = json.loads(r[0])
            assert isinstance(refs, list)
            total_evidence_refs += len(refs)

        assert total_evidence_refs == 498, f"Expected 498 total evidence references, got {total_evidence_refs}"


class TestEulerFinanceIncidentInvestigation:
    """End-to-end investigation of the Euler Finance incident on real Ethereum data."""

    def test_euler_five_readonly_tools_workflow(self, ro_real_db):
        # 1. Alert investigation
        alerts = get_alerts(ro_real_db, rule_id="large_transfer", limit=50)
        assert len(alerts) > 0
        euler_alerts = [
            a for a in alerts if any(
                isinstance(ref, dict) and ref.get("tx_hash", "").lower() == EULER_TX_HASH
                for ref in a["evidence_refs"]
            )
        ]
        assert len(euler_alerts) >= 1

        # 2. Transaction evidence retrieval
        tx_info = get_tx(ro_real_db, EULER_TX_HASH)
        assert tx_info is not None
        assert tx_info["block_number"] == EULER_BLOCK
        assert len(tx_info["transfers"]) >= 10
        assert any(t["amount_raw"] == EULER_AMOUNT_RAW for t in tx_info["transfers"])

        # 3. Address history analysis
        history = get_address_history(ro_real_db, EULER_TO_ADDR, limit=50)
        assert len(history) == 4
        assert any(h["tx_hash"].lower() == EULER_TX_HASH for h in history)

        # 4. Counterparty analysis
        counterparties = get_counterparties(ro_real_db, EULER_TO_ADDR, limit=25)
        assert len(counterparties) >= 2
        assert any(cp["counterparty"].lower() == EULER_FROM_ADDR for cp in counterparties)

        # 5. Chronological timeline reconstruction
        timeline = get_timeline(ro_real_db, case_id="euler", limit=100)
        assert len(timeline) >= 5
        event_types = {e["event_type"] for e in timeline}
        assert "transfer" in event_types or "alert" in event_types

    def test_euler_full_investigator_and_ref_checker(self, ro_real_db):
        test_model = create_test_model(
            call_tools=[
                "tool_get_alerts",
                "tool_get_tx",
                "tool_get_address_history",
                "tool_get_counterparties",
                "tool_get_timeline",
            ],
            custom_output_args={
                "case_id": "euler-finance",
                "observed_facts": [
                    {
                        "statement": "Address 0x028171bca77440897b824ca71d1c56cac55b68a3 transferred 30000000 DAI to 0xebc29199c817dc47ba12e3f86102564d640cbf99 in block 16817996",
                        "tx_hash": EULER_TX_HASH,
                        "block_number": EULER_BLOCK,
                        "from_addr": EULER_FROM_ADDR,
                        "to_addr": EULER_TO_ADDR,
                        "asset_id": EULER_ASSET_DAI,
                        "amount_raw": EULER_AMOUNT_RAW,
                        "evidence_refs": [
                            f"alert:{EULER_ALERT_ID}",
                            f"tx:{EULER_TX_HASH}",
                            f"block:{EULER_BLOCK}",
                        ],
                    }
                ],
                "rule_detections": [
                    {
                        "rule_id": "large_transfer",
                        "alert_id": EULER_ALERT_ID,
                        "severity": "high",
                        "score": 1.0,
                        "reason": "Large DAI transfer >= 99th percentile threshold",
                        "evidence_refs": [f"tx:{EULER_TX_HASH}"],
                    }
                ],
                "external_labels": [
                    {
                        "source": "Aave V2 Pool Registry",
                        "address_or_tx": EULER_FROM_ADDR,
                        "category": "lending_pool",
                        "entity_name": "Aave: aDAI Token V2",
                        "is_verified": True,
                    }
                ],
                "analyst_interpretations": [
                    {
                        "hypothesis_id": "HYP-EULER-01",
                        "interpretation": "The 30M DAI flash loan initiated a sequence of leveraged mint and donate calls.",
                        "confidence": 0.95,
                        "supporting_fact_indices": [0],
                        "competing_hypotheses": ["Institutional liquidity rebalancing"],
                    }
                ],
                "chronological_timeline": [
                    f"Block {EULER_BLOCK}: 30,000,000 DAI transferred in tx {EULER_TX_HASH}"
                ],
                "investigative_observations": [
                    "Multiple high-value DAI transfers occurred within single transaction execution."
                ],
                "conclusions": [
                    "Verified 30M DAI transfer in block 16817996 matching Rule Engine alert R1."
                ],
                "uncertainty_and_limitations": [
                    "Subsequent cross-chain bridge hops after block 16818110 are outside the current window."
                ],
            },
        )

        inv = ForensicInvestigator(
            config=AIConfig(provider="test", max_tool_steps=5),
            model=test_model,
            readonly_db=ro_real_db,
            strict_ref_checker=True,
        )

        res = inv.investigate(
            case_id="euler-finance",
            query=f"Investigate Euler Finance tx {EULER_TX_HASH}",
            input_refs=[f"tx:{EULER_TX_HASH}", f"alert:{EULER_ALERT_ID}"],
        )

        assert res.has_content_mismatch is False
        assert res.content_match_ratio == 1.0
        assert res.existence_ref_ratio == 1.0
        assert len(res.mismatches) == 0
        assert res.tool_calls_log["summary"]["successful_steps"] == 5

        # Independent two-stage verification check
        ref_check = check_investigation_output(res.output, ro_real_db)
        assert ref_check.is_valid is True
        assert ref_check.content_match_ratio == 1.0
        assert ref_check.existence_ref_ratio == 1.0


class TestCurveAlchemixIncidentInvestigation:
    """End-to-end investigation of the Curve / Alchemix incident on real Ethereum data."""

    def test_curve_five_readonly_tools_workflow(self, ro_real_db):
        # 1. Alert investigation
        alerts = get_alerts(ro_real_db, rule_id="large_transfer", limit=200)
        curve_alerts = [
            a for a in alerts if any(
                isinstance(ref, dict) and ref.get("tx_hash", "").lower() == CURVE_TX_HASH
                for ref in a["evidence_refs"]
            )
        ]
        assert len(curve_alerts) >= 1

        # 2. Transaction evidence retrieval
        tx_info = get_tx(ro_real_db, CURVE_TX_HASH)
        assert tx_info is not None
        assert tx_info["block_number"] == CURVE_BLOCK
        assert len(tx_info["transfers"]) >= 5

        # 3. Address history analysis
        history = get_address_history(ro_real_db, CURVE_FROM_ADDR, limit=50)
        assert len(history) >= 3

        # 4. Counterparty analysis
        counterparties = get_counterparties(ro_real_db, CURVE_FROM_ADDR, limit=25)
        assert len(counterparties) >= 1

        # 5. Chronological timeline reconstruction
        timeline = get_timeline(ro_real_db, case_id="curve", limit=100)
        assert len(timeline) >= 5

    def test_curve_full_investigator_and_ref_checker(self, ro_real_db):
        test_model = create_test_model(
            call_tools=[
                "tool_get_alerts",
                "tool_get_tx",
                "tool_get_address_history",
                "tool_get_counterparties",
                "tool_get_timeline",
            ],
            custom_output_args={
                "case_id": "curve-alchemix",
                "observed_facts": [
                    {
                        "statement": "Address 0x30fb95794a2051abe30a67892b3a1fa73947aee5 transferred 7258701569350004501158 wei NATIVE to 0xdce5d6b41c32f578f875efffc0d422c57a75d7d8 in block 17806772",
                        "tx_hash": CURVE_TX_HASH,
                        "block_number": CURVE_BLOCK,
                        "from_addr": CURVE_FROM_ADDR,
                        "to_addr": CURVE_TO_ADDR,
                        "asset_id": CURVE_ASSET_NATIVE,
                        "amount_raw": CURVE_AMOUNT_RAW,
                        "evidence_refs": [
                            f"alert:{CURVE_ALERT_ID}",
                            f"tx:{CURVE_TX_HASH}",
                            f"block:{CURVE_BLOCK}",
                        ],
                    }
                ],
                "rule_detections": [
                    {
                        "rule_id": "large_transfer",
                        "alert_id": CURVE_ALERT_ID,
                        "severity": "high",
                        "score": 1.0,
                        "reason": "Large internal ETH transfer detected",
                        "evidence_refs": [f"tx:{CURVE_TX_HASH}"],
                    }
                ],
                "analyst_interpretations": [
                    {
                        "hypothesis_id": "HYP-CURVE-01",
                        "interpretation": "Internal ETH movement during pool liquidity extraction and WETH unwrap/wrap cycle.",
                        "confidence": 0.92,
                        "supporting_fact_indices": [0],
                    }
                ],
                "chronological_timeline": [
                    f"Block {CURVE_BLOCK}: Internal ETH transfer in tx {CURVE_TX_HASH}"
                ],
                "conclusions": [
                    "Verified internal ETH transfer of 7,258.70 ETH in block 17806772."
                ],
                "uncertainty_and_limitations": [
                    "MEV builder private relay submission metadata is off-chain."
                ],
            },
        )

        inv = ForensicInvestigator(
            config=AIConfig(provider="test", max_tool_steps=5),
            model=test_model,
            readonly_db=ro_real_db,
            strict_ref_checker=True,
        )

        res = inv.investigate(
            case_id="curve-alchemix",
            query=f"Investigate Curve Alchemix tx {CURVE_TX_HASH}",
            input_refs=[f"tx:{CURVE_TX_HASH}", f"alert:{CURVE_ALERT_ID}"],
        )

        assert res.has_content_mismatch is False
        assert res.content_match_ratio == 1.0
        assert res.existence_ref_ratio == 1.0
        assert len(res.mismatches) == 0


class TestStagingRangeCollectionAndCLI:
    """Verifies isolated staging block collection and CLI investigation execution."""

    def test_missing_range_staging_20_blocks_succeeds_and_21_rejected(self, real_db_baseline_sha256):
        staging_conn = get_staging_connection()
        tracker = ToolBudgetManager(max_steps=5)

        # 20 blocks inclusive: 16817980..16817999 (16817999 - 16817980 + 1 = 20)
        res = collect_missing_range(
            start_block=16817980,
            end_block=16817999,
            staging_db=staging_conn,
            tracker=tracker,
        )
        assert res["status"] == "success"
        assert res["blocks_count"] == 20

        # 21 blocks inclusive: 16817980..16818000 -> must raise RangeLimitExceeded
        with pytest.raises(RangeLimitExceeded):
            collect_missing_range(
                start_block=16817980,
                end_block=16818000,
                staging_db=staging_conn,
                tracker=tracker,
            )
        staging_conn.close()

    def test_cli_investigate_command_end_to_end(self, tmp_path, real_db_baseline_sha256):
        import shutil

        euler_db_copy = tmp_path / "euler_real_p4_copy.db"
        curve_db_copy = tmp_path / "curve_real_p4_copy.db"
        shutil.copy2(REAL_P4_DB_PATH, euler_db_copy)
        shutil.copy2(REAL_P4_DB_PATH, curve_db_copy)

        assert _compute_sha256(euler_db_copy) == real_db_baseline_sha256
        assert _compute_sha256(curve_db_copy) == real_db_baseline_sha256

        # Case A: Euler Finance CLI Investigation
        euler_out = tmp_path / "euler_investigation_out.json"
        euler_cmd = [
            sys.executable,
            "-m",
            "forensics.cli",
            "investigate",
            "--case-id",
            "euler-finance",
            "--db",
            str(euler_db_copy),
            "--query",
            "Investigate Euler Finance Ethereum exploit and address 0xb66cd966670d962c227b3eaba30a872dbfb995db. Retrieve on-chain evidence and verify observed facts.",
            "--provider",
            "test",
            "--max-steps",
            "5",
            "--strict-ref-check",
            "--out",
            str(euler_out),
        ]
        proc_euler = subprocess.run(
            euler_cmd,
            cwd=str(Path(__file__).resolve().parents[1]),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc_euler.returncode == 0, f"Euler CLI failed: {proc_euler.stderr}"
        assert euler_out.exists()
        euler_payload = json.loads(euler_out.read_text(encoding="utf-8"))
        assert euler_payload["case_id"] == "euler-finance"
        assert euler_payload["output"]["case_id"] == "euler-finance"
        assert euler_payload["ref_check_status"] == "PASS"
        assert euler_payload["checked_facts_count"] == 10
        assert len(euler_payload["output"]["observed_facts"]) == 10
        assert len(euler_payload["output"]["rule_detections"]) == 15
        assert len(euler_payload["output"]["chronological_timeline"]) >= 10
        assert len(euler_payload["output"]["conclusions"]) >= 1
        assert euler_payload["referenced_canonical_tx_count"] >= 5
        assert euler_payload["content_match_ratio"] == 1.0
        assert euler_payload["existence_ref_ratio"] == 1.0
        assert euler_payload["has_content_mismatch"] is False
        assert euler_payload["tool_calls_summary"]["attempted_steps"] == 5
        assert euler_payload["tool_calls_summary"]["successful_steps"] == 5
        assert euler_payload["tool_calls_summary"]["budget_exhausted"] is False

        # Case B: Curve / Alchemix CLI Investigation
        curve_out = tmp_path / "curve_investigation_out.json"
        curve_cmd = [
            sys.executable,
            "-m",
            "forensics.cli",
            "investigate",
            "--case-id",
            "curve-alchemix",
            "--db",
            str(curve_db_copy),
            "--query",
            "Investigate Curve Alchemix Vyper reentrancy exploit and address 0xdce5d6b41c32f578f875efffc0d422c57a75d7d8. Retrieve on-chain evidence and verify observed facts.",
            "--provider",
            "test",
            "--max-steps",
            "5",
            "--strict-ref-check",
            "--out",
            str(curve_out),
        ]
        proc_curve = subprocess.run(
            curve_cmd,
            cwd=str(Path(__file__).resolve().parents[1]),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc_curve.returncode == 0, f"Curve CLI failed: {proc_curve.stderr}"
        assert curve_out.exists()
        curve_payload = json.loads(curve_out.read_text(encoding="utf-8"))
        assert curve_payload["case_id"] == "curve-alchemix"
        assert curve_payload["output"]["case_id"] == "curve-alchemix"
        assert curve_payload["ref_check_status"] == "PASS"
        assert curve_payload["checked_facts_count"] == 10
        assert len(curve_payload["output"]["observed_facts"]) == 10
        assert len(curve_payload["output"]["rule_detections"]) == 15
        assert len(curve_payload["output"]["chronological_timeline"]) >= 10
        assert len(curve_payload["output"]["conclusions"]) >= 1
        assert curve_payload["referenced_canonical_tx_count"] >= 5
        assert curve_payload["content_match_ratio"] == 1.0
        assert curve_payload["existence_ref_ratio"] == 1.0
        assert curve_payload["has_content_mismatch"] is False
        assert curve_payload["tool_calls_summary"]["attempted_steps"] == 5
        assert curve_payload["tool_calls_summary"]["successful_steps"] == 5
        assert curve_payload["tool_calls_summary"]["budget_exhausted"] is False

        # Verify database copies and canonical DB remain byte-for-byte unchanged
        assert _compute_sha256(euler_db_copy) == real_db_baseline_sha256
        assert _compute_sha256(curve_db_copy) == real_db_baseline_sha256


class TestLiveGeminiSmokeConditional:
    """Controlled live Gemini Flash smoke test (executes only if API key is present)."""

    def test_live_gemini_flash_smoke(self, ro_real_db):
        api_key, src = resolve_api_key()
        if not api_key:
            pytest.skip(
                "LIVE_GEMINI_PENDING: Neither GOOGLE_API_KEY nor GEMINI_API_KEY is configured in environment."
            )

        cfg = AIConfig(
            provider="gemini",
            model_name="gemini-2.5-flash",
            max_tool_steps=3,
            request_limit=4,
            allow_offline_fallback=False,
        )
        inv = ForensicInvestigator(config=cfg, readonly_db=ro_real_db)
        res = inv.investigate(
            case_id="euler-smoke",
            query=f"Retrieve transaction {EULER_TX_HASH} and summarize observed facts.",
        )
        assert res.output.case_id is not None
