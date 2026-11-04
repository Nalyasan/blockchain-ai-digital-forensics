"""Test Suite 3: P8 MITRE ATT&CK Mapping & AI Investigator P5 Safe Integration.

Tests:
1. MITRE ATT&CK taxonomy catalog (T1566.002, T1027, T1048.003, T1499.004, T1565.001).
2. Mandatory canonical evidence grounding: UnsubstantiatedMappingError on empty refs.
3. Technique-specific forensic triggers across DeFi exploit patterns.
4. AI Investigator P5 schema integration (MLAnomalyDetection, MitreAttackMapping).
5. Strict field separation: ObservedFact rejects ML/MITRE vocabulary (anomalous, mitre, t1027).
6. Tool whitelist verification: get_ml_anomaly_analysis in AUTHORIZED_TOOLS.
7. End-to-end execution of get_ml_anomaly_analysis against real_p4.db.
8. Two-stage reference checker verification of ML & MITRE evidence refs (detecting hallucinated hashes).
9. Prompt injection defense preservation and tool call budget tracking.
"""
from __future__ import annotations

import sqlite3
import pytest
from pydantic import ValidationError

from forensics.paths import REAL_P4_DB
from forensics.ai.schemas import (
    ForensicInvestigationOutput,
    MLAnomalyDetection,
    MitreAttackMapping,
    ObservedFact,
    RuleDetection,
)
from forensics.ai.tools import (
    AUTHORIZED_TOOLS,
    ToolCallBudgetTracker,
    execute_guarded_tool,
    get_ml_anomaly_analysis,
)
from forensics.ai.investigator import ForensicInvestigator
from forensics.ai.ref_checker import check_investigation_output
from forensics.ml.mitre import (
    MITRE_DEFI_TAXONOMY,
    MitreMappingEngine,
    UnsubstantiatedMappingError,
    validate_canonical_evidence_refs,
)


class TestMitreMappingEngine:
    """Verifies MITRE ATT&CK DeFi mapping rules and evidence grounding invariants."""

    def test_taxonomy_catalog_completeness(self):
        expected_keys = {"T1566.002", "T1027", "T1048.003", "T1499.004", "T1565.001"}
        assert expected_keys.issubset(set(MITRE_DEFI_TAXONOMY.keys()))
        for key, defn in MITRE_DEFI_TAXONOMY.items():
            assert defn.technique_id == key
            assert len(defn.technique_name) > 0
            assert len(defn.tactic) > 0
            assert len(defn.sub_tactic_defi) > 0

    def test_evidence_ref_canonical_normalization(self):
        raw_refs = [
            "0x" + "a"*64,               # Bare 64-hex tx
            "tx:0x" + "b"*64,            # Canonical tx
            "c"*64,                      # Bare 64-hex alert id
            "alert:alt_1234",            # Canonical alert
            "block:16817990",            # Block ref
            "invalid_random_string",     # Invalid -> excluded
        ]
        norm = validate_canonical_evidence_refs(raw_refs)
        assert f"tx:0x{'a'*64}" in norm
        assert f"tx:0x{'b'*64}" in norm
        assert f"alert:{'c'*64}" in norm
        assert "alert:alt_1234" in norm
        assert "block:16817990" in norm
        assert "invalid_random_string" not in norm

    def test_rejection_of_unsubstantiated_mapping(self):
        engine = MitreMappingEngine(strict_evidence=True)
        # Attempt to map anomaly with zero evidence references
        with pytest.raises(UnsubstantiatedMappingError, match="zero verified canonical evidence references"):
            engine.map_anomaly(
                features={"max_single_out_ratio": 0.95},
                anomaly_score=0.90,
                rule_alerts=[],
                evidence_refs=[],
            )

    def test_trigger_t1566_approval_drain(self):
        engine = MitreMappingEngine(strict_evidence=True)
        valid_ref = "tx:0x" + "1"*64
        mappings = engine.map_anomaly(
            features={"max_single_out_ratio": 0.85, "volume_out_normalized": 18.5},
            anomaly_score=0.80,
            rule_alerts=[{"rule_id": "large_transfer", "alert_id": "a"*64, "evidence_refs": []}],
            evidence_refs=[valid_ref],
        )
        tech_ids = [m["technique_id"] for m in mappings]
        assert "T1566.002" in tech_ids

    def test_trigger_t1048_rapid_exfiltration(self):
        engine = MitreMappingEngine(strict_evidence=True)
        valid_ref = "tx:0x" + "2"*64
        mappings = engine.map_anomaly(
            features={"pass_through_ratio": 0.95, "turnover_latency_min": 1.0},
            anomaly_score=0.85,
            rule_alerts=[{"rule_id": "rapid_pass_through", "alert_id": "b"*64, "evidence_refs": []}],
            evidence_refs=[valid_ref],
        )
        tech_ids = [m["technique_id"] for m in mappings]
        assert "T1048.003" in tech_ids

    def test_trigger_t1027_mixer_layering(self):
        engine = MitreMappingEngine(strict_evidence=True)
        valid_ref = "tx:0x" + "3"*64
        mappings = engine.map_anomaly(
            features={"unique_counterparties_out": 5.0, "token_diversity": 3.0},
            anomaly_score=0.75,
            rule_alerts=[{"rule_id": "fan_in_out", "alert_id": "c"*64, "evidence_refs": []}],
            evidence_refs=[valid_ref],
        )
        tech_ids = [m["technique_id"] for m in mappings]
        assert "T1027" in tech_ids

    def test_trigger_t1499_burst_spam(self):
        engine = MitreMappingEngine(strict_evidence=True)
        valid_ref = "tx:0x" + "4"*64
        mappings = engine.map_anomaly(
            features={"tx_velocity": 12.0, "burstiness_std": 1.0},
            anomaly_score=0.70,
            rule_alerts=[{"rule_id": "high_frequency", "alert_id": "d"*64, "evidence_refs": []}],
            evidence_refs=[valid_ref],
        )
        tech_ids = [m["technique_id"] for m in mappings]
        assert "T1499.004" in tech_ids

    def test_trigger_t1565_state_manipulation(self):
        engine = MitreMappingEngine(strict_evidence=True)
        valid_ref = "tx:0x" + "5"*64
        mappings = engine.map_anomaly(
            features={
                "tx_velocity": 5.0,
                "volume_in_normalized": 15.0,
                "volume_out_normalized": 15.0,
                "token_diversity": 2.0,
                "turnover_latency_min": 0.0,
            },
            anomaly_score=0.85,
            rule_alerts=[{"rule_id": "large_transfer", "alert_id": "e"*64, "evidence_refs": []}],
            evidence_refs=[valid_ref],
        )
        tech_ids = [m["technique_id"] for m in mappings]
        assert "T1565.001" in tech_ids


class TestAIInvestigatorMitreIntegration:
    """Verifies schema extension, strict field separation, and tool guardrails."""

    def test_strict_field_separation_observed_fact_rejects_ml_mitre_terms(self):
        valid_tx = "0x" + "1"*64
        valid_addr = "0x" + "2"*40

        # Objective physical fact passes
        fact = ObservedFact(
            statement=f"Transfer of 100 DAI executed from {valid_addr} to {valid_addr} in block 16817990.",
            tx_hash=valid_tx,
            block_number=16817990,
            from_addr=valid_addr,
            to_addr=valid_addr,
            asset_id="0x6b175474e89094c44da98b954eedeac495271d0f",
            amount_raw="100000000000000000000",
            evidence_refs=[f"tx:{valid_tx}"],
        )
        assert fact.amount_raw == "100000000000000000000"

        # Attempting to inject ML or MITRE terms into ObservedFact.statement must fail
        violating_statements = [
            f"Observed anomalous transaction {valid_tx}",
            f"Predicted attack pattern on {valid_addr}",
            f"Transfer matches MITRE T1027 obfuscation technique",
            f"SHAP attribution indicates suspicious exfiltration",
        ]

        for stmt in violating_statements:
            with pytest.raises(ValidationError) as exc:
                ObservedFact(
                    statement=stmt,
                    tx_hash=valid_tx,
                    block_number=16817990,
                    from_addr=valid_addr,
                    to_addr=valid_addr,
                    asset_id="0x6b175474e89094c44da98b954eedeac495271d0f",
                    amount_raw="100000000000000000000",
                    evidence_refs=[f"tx:{valid_tx}"],
                )
            assert "Field separation violation" in str(exc.value)

    def test_forensic_investigation_output_with_ml_and_mitre(self):
        valid_addr = "0x" + "a"*40
        valid_tx = "0x" + "b"*64

        ml_det = MLAnomalyDetection(
            model_id="anomaly_detector_v1",
            model_sha256="c"*64,
            entity_address=valid_addr,
            score=0.92,
            classification="anomalous",
            top_features=["high_tx_velocity: +0.40"],
            xai_attributions={"tx_velocity": 0.40},
            mitre_techniques=["T1048.003"],
            evidence_refs=[f"tx:{valid_tx}"],
        )

        mitre_map = MitreAttackMapping(
            technique_id="T1048.003",
            technique_name="Exfiltration Over Alternative Protocol: Bridge Hop",
            tactic="Exfiltration",
            confidence=0.88,
            evidence_refs=[f"tx:{valid_tx}"],
            rationale="Pass-through ratio of 0.95 with turnover latency of 1 block.",
        )

        output = ForensicInvestigationOutput(
            case_id="euler-ml-case",
            ml_detections=[ml_det],
            mitre_mappings=[mitre_map],
        )
        assert len(output.ml_detections) == 1
        assert len(output.mitre_mappings) == 1
        assert output.ml_detections[0].score == 0.92

    def test_get_ml_anomaly_analysis_in_authorized_tools(self):
        assert "get_ml_anomaly_analysis" in AUTHORIZED_TOOLS

    def test_execute_get_ml_anomaly_analysis_on_real_data(self):
        if not REAL_P4_DB.exists():
            pytest.skip("real_p4.db not present at default path")

        euler_attacker = "0xebc29199c817dc47ba12e3f86102564d640cbf99"
        result = get_ml_anomaly_analysis(euler_attacker, db_path=REAL_P4_DB)

        assert "error" not in result
        assert result["entity_address"] == euler_attacker.lower()
        assert 0.0 <= result["score"] <= 1.0
        assert result["classification"] in {"normal", "suspicious", "anomalous"}
        assert len(result["features"]) == 10
        assert isinstance(result["top_features"], list)
        assert len(result["evidence_refs"]) > 0

    def test_ref_checker_detects_hallucinated_ml_and_mitre_refs(self):
        """Two-stage reference checker must fail if ML or MITRE cites fabricated tx hashes."""
        # Create an in-memory test database with 1 legitimate transfer
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            "CREATE TABLE transactions (tx_hash TEXT PRIMARY KEY, block_number INT, from_addr TEXT, to_addr TEXT)"
        )
        conn.execute("CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, rule_id TEXT)")
        conn.execute(
            "CREATE TABLE asset_transfers (chain_id INT, block_number INT, block_hash TEXT, tx_hash TEXT, log_index INT, asset_id TEXT, from_addr TEXT, to_addr TEXT, amount_raw TEXT)"
        )

        real_tx = "0x" + "1"*64
        fake_tx = "0x" + "dead"*16
        conn.execute(
            "INSERT INTO transactions VALUES (?, 100, '0xaaa', '0xbbb')",
            (real_tx,),
        )
        conn.commit()

        # Case 1: Valid references pass
        valid_out = {
            "case_id": "test_case",
            "observed_facts": [],
            "rule_detections": [],
            "ml_detections": [{
                "model_id": "m1",
                "model_sha256": "0"*64,
                "entity_address": "0x" + "1"*40,
                "score": 0.8,
                "classification": "anomalous",
                "evidence_refs": [f"tx:{real_tx}"],
            }],
            "mitre_mappings": [{
                "technique_id": "T1048.003",
                "technique_name": "Bridge Hop",
                "tactic": "Exfiltration",
                "confidence": 0.8,
                "evidence_refs": [f"tx:{real_tx}"],
                "rationale": "Valid transfer exfiltration",
            }],
        }
        res_valid = check_investigation_output(valid_out, db=conn)
        assert res_valid.existence_ref_ratio == 1.0

        # Case 2: Hallucinated tx reference causes missing_refs and existence failure
        tampered_out = {
            "case_id": "test_case",
            "observed_facts": [],
            "rule_detections": [],
            "ml_detections": [{
                "model_id": "m1",
                "model_sha256": "0"*64,
                "entity_address": "0x" + "1"*40,
                "score": 0.8,
                "classification": "anomalous",
                "evidence_refs": [f"tx:{fake_tx}"],  # Fake reference!
            }],
            "mitre_mappings": [],
        }
        res_tampered = check_investigation_output(tampered_out, db=conn)
        assert res_tampered.existence_ref_ratio < 1.0
        assert f"tx:{fake_tx}" in res_tampered.missing_refs

        conn.close()

    def test_tool_budget_tracking_with_ml_tool(self):
        tracker = ToolCallBudgetTracker(max_steps=5)
        # Execute tool through guarded wrapper
        def mock_ml_tool(entity_address):
            return {"score": 0.9, "entity_address": entity_address}

        res = execute_guarded_tool(
            "get_ml_anomaly_analysis",
            {"entity_address": "0x" + "a"*40},
            {"get_ml_anomaly_analysis": mock_ml_tool},
            tracker,
        )
        assert res["score"] == 0.9
        assert tracker.attempted_tool_calls == 1
        assert tracker.successful_tool_calls == 1
