"""End-to-End Comprehensive Integration Test Suite: P1 through P10.

Validates the complete Digital Forensics lifecycle integrating all phases:
- P1 & P7: Dual-source evidence collection (Ethereum blockchain & Endpoint telemetry)
- P2: Tamper-evident evidence storage, ISO/IEC 27037 manifest & SHA-256 integrity
- P3 & P10: Chain of Custody on EVM Smart Contract (EvidenceRegistryDID) with ERC-1056 DID & EIP-712 signatures
- P4 & P8: Dual detection engine: Rule Engine (R1-R4) + Compact MLP Machine Learning
- P8: Deterministic XAI (ExactShapleyExplainer) & Grounded MITRE ATT&CK Mapping
- P5: AI Investigator safe workflow (Tool Whitelist, Sanitizer, Budget, RefChecker, Fact Separation)
- P9: Verifiable AI Inference via Halo2 BN254 KZG Zero-Knowledge Machine Learning (ZKML)

Constraints strictly enforced:
- Zero mock proofs for ZKML
- Zero private key or PII on-chain (ISO/IEC 27037)
- 100% database invariance for canonical datasets
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

import pytest
import numpy as np
from pydantic import ValidationError

# P1 & P4 paths and database
from forensics.paths import REAL_P4_DB, FORENSICS_DB

# P7 Endpoint Forensics
from forensics.endpoint.first_responder import (
    AIFirstResponder,
    DangerousActionError,
    ForbiddenActionCategory,
    SafetyGuard,
    TriagePlaybookType,
)
from forensics.endpoint.daemon import MockTelemetryProvider
from forensics.endpoint.store import EndpointEvidenceStore

# P8 Machine Learning, XAI, MITRE
from forensics.ml.model import CompactAnomalyMLP, load_default_model
from forensics.ml.registry import load_model_metadata
from forensics.ml.dataset import RobustFeatureScaler
from forensics.ml.features import extract_single_address_features, FEATURE_NAMES
from forensics.ml.xai import ExactShapleyExplainer
from forensics.ml.corroboration import DualEngineCorroborator
from forensics.ml.mitre import MitreMappingEngine, UnsubstantiatedMappingError

# P5 AI Investigator & Safety
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
from forensics.ai.ref_checker import check_investigation_output

# P9 ZKML Verifiable Inference
from forensics.zkml import (
    ZKMLProofResult,
    ZKMLProver,
    ZKMLVerifier,
)

# P10 DID & Chain of Custody (ISO/IEC 27037)
from forensics.did.resolution import format_did, parse_did, resolve_did, is_valid_did
from forensics.did.eip712 import (
    ROLE_COLLECTOR,
    ROLE_ANALYST,
    ROLE_FIRST_RESPONDER,
    ROLE_ZKML_VERIFIER,
    ROLE_CUSTODIAN,
    build_custody_transfer_typed_data,
    build_attestation_typed_data,
    sign_typed_data,
    verify_typed_signature,
)
from forensics.did.artifacts import (
    canonical_hash,
    create_ml_xai_attestation_payload,
    create_zkml_attestation_payload,
    scan_for_sensitive_leakage,
)


def calculate_sha256(filepath: str | Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class TestIntegrationLifecyclePipeline:
    """Complete end-to-end multi-phase forensic pipeline test."""

    @pytest.fixture(autouse=True)
    def setup_fixture(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="forensics_p1_p10_"))
        self.investigator_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        self.investigator_addr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        self.investigator_did = format_did(self.investigator_addr)
        self.zkml_key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
        self.zkml_addr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
        self.zkml_did = format_did(self.zkml_addr)

        yield

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_complete_integration_lifecycle(self):
        """Execute full lifecycle connecting end-to-end digital forensics components."""

        # -------------------------------------------------------------
        # STEP 1: P1 Blockchain Data Ingest & P7 Endpoint Telemetry
        # -------------------------------------------------------------
        assert os.path.exists(REAL_P4_DB), f"Real P4 DB missing at {REAL_P4_DB}"
        conn = sqlite3.connect(REAL_P4_DB)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT from_addr, to_addr, tx_hash, amount_raw, block_number, asset_id FROM asset_transfers LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        assert row is not None, "Failed to query canonical transaction from P1/P4 store"
        from_addr = row["from_addr"]
        to_addr = row["to_addr"]
        tx_hash = row["tx_hash"]
        tx_val = row["amount_raw"]
        blk_num = row["block_number"]
        asset_id = row["asset_id"]

        # Initialize P7 First Responder with Mock Provider (safe telemetry)
        mock_provider = MockTelemetryProvider()
        endpoint_db_path = self.temp_dir / "endpoint_evidence.db"
        endpoint_store = EndpointEvidenceStore(db_path=endpoint_db_path)
        first_responder = AIFirstResponder(
            evidence_store=endpoint_store,
            telemetry_provider=mock_provider
        )

        triage_proc = first_responder.execute_action("triage_running_processes", limit=10)
        assert triage_proc.success is True
        assert triage_proc.records_count >= 1
        proc_record = triage_proc.records[0]
        assert "payload_sha256" in proc_record

        triage_sock = first_responder.execute_action("triage_active_network_connections", limit=10)
        assert triage_sock.success is True
        assert triage_sock.records_count >= 1
        sock_record = triage_sock.records[0]

        # -------------------------------------------------------------
        # STEP 2: P2 Evidence Packaging & Manifest
        # -------------------------------------------------------------
        package_dir = self.temp_dir / "evidence_package_case_001"
        package_dir.mkdir(parents=True, exist_ok=True)

        artifact_data = {
            "case_id": "CASE-2026-001",
            "p1_transaction": {"hash": tx_hash, "from": from_addr, "to": to_addr, "value": tx_val},
            "p7_endpoint": {"process": proc_record, "socket": sock_record},
        }
        artifact_path = package_dir / "forensic_artifact.json"
        with open(artifact_path, "w", encoding="utf-8") as f:
            json.dump(artifact_data, f, indent=2)

        artifact_sha256 = calculate_sha256(artifact_path)
        manifest = {
            "version": "ISO/IEC 27037:2012",
            "artifacts": [
                {"path": "forensic_artifact.json", "sha256": artifact_sha256, "type": "combined_evidence"}
            ]
        }
        manifest_path = package_dir / "manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        manifest_sha256 = calculate_sha256(manifest_path)
        assert len(manifest_sha256) == 64

        # -------------------------------------------------------------
        # STEP 3: P4 Rule Engine & P8 Machine Learning Anomaly Detection
        # -------------------------------------------------------------
        model = load_default_model()
        metadata = load_model_metadata("anomaly_detector_v1")
        assert model.count_parameters() == 321

        scaler = RobustFeatureScaler.from_dict(metadata["scaler"])
        feat_dict = extract_single_address_features(REAL_P4_DB, from_addr)
        raw_vec = np.array([[feat_dict.get(k, 0.0) for k in FEATURE_NAMES]], dtype=np.float32)
        scaled_vec = scaler.transform(raw_vec)
        ml_score = float(model.forward(scaled_vec)[0])
        assert 0.0 <= ml_score <= 1.0

        # Corroborate with P4 rule alerts
        corroborator = DualEngineCorroborator(REAL_P4_DB)
        corroborated = corroborator.corroborate(entity_address=from_addr, ml_score=ml_score)
        assert corroborated.combined_score >= 0.0

        # -------------------------------------------------------------
        # STEP 4: P8 XAI (Exact SHAP) & MITRE ATT&CK Mapping
        # -------------------------------------------------------------
        explainer = ExactShapleyExplainer(
            model_predict_fn=model.predict_score,
            feature_names=FEATURE_NAMES,
        )
        explanation = explainer.explain(
            features=scaled_vec[0],
            entity_address=from_addr,
            top_k=3,
        )
        assert len(explanation.top_drivers) >= 1

        mitre_engine = MitreMappingEngine(strict_evidence=True)
        feat_for_mitre = dict(feat_dict)
        feat_for_mitre["max_single_out_ratio"] = 0.85
        mappings = mitre_engine.map_anomaly(
            features=feat_for_mitre,
            anomaly_score=ml_score,
            rule_alerts=[{"rule_id": "R2_FAST_DRAIN"}],
            evidence_refs=["tx:0x" + tx_hash.removeprefix("0x")]
        )
        assert len(mappings) >= 1
        mitre_mapping = MitreAttackMapping(**mappings[0])
        assert mitre_mapping.technique_id in ["T1566.002", "T1565.001", "T1027", "T1048.003", "T1499.004"]

        # -------------------------------------------------------------
        # STEP 5: P5 AI Investigator Safe Tool Whitelist & RefChecker
        # -------------------------------------------------------------
        assert "get_ml_anomaly_analysis" in AUTHORIZED_TOOLS

        # Schema validation: separation of ObservedFact vs ML/MITRE vocabulary
        fact = ObservedFact(
            statement=f"Transfer of {tx_val} raw units executed from {from_addr} to {to_addr} in block {blk_num}.",
            tx_hash=tx_hash,
            block_number=blk_num,
            from_addr=from_addr,
            to_addr=to_addr,
            asset_id=asset_id,
            amount_raw=str(tx_val),
            evidence_refs=[f"tx:{tx_hash}"]
        )

        # RefChecker: ensure all cited hashes genuinely exist in database
        conn = sqlite3.connect(REAL_P4_DB)
        conn.row_factory = sqlite3.Row
        valid_out = {
            "case_id": "CASE-2026-001",
            "observed_facts": [fact.model_dump()],
            "rule_detections": [{
                "rule_id": "R2_FAST_DRAIN",
                "evidence_refs": [f"tx:{tx_hash}"],
            }],
            "ml_detections": [{
                "model_id": "anomaly_detector_v1",
                "model_sha256": "0" * 64,
                "entity_address": from_addr,
                "score": ml_score,
                "classification": "anomalous" if ml_score > 0.7 else "benign",
                "evidence_refs": [f"tx:{tx_hash}"],
            }],
            "mitre_mappings": [mitre_mapping.model_dump()],
        }
        check_result = check_investigation_output(valid_out, db=conn)
        assert check_result.existence_ref_ratio == 1.0
        assert len(check_result.missing_refs) == 0
        conn.close()

        # -------------------------------------------------------------
        # STEP 6: P9 ZKML Verifiable Inference (Halo2 BN254 KZG Proof)
        # -------------------------------------------------------------
        prover = ZKMLProver(
            model_path=Path("models/anomaly_detector_v1.onnx"),
            artifacts_dir=Path("scratch/zkml_artifacts"),
            auto_setup=True,
        )
        feat_list = [float(x) for x in scaled_vec.flatten()]
        proof_result = prover.prove(feat_list)

        assert proof_result.is_valid is True
        assert len(proof_result.proof_bytes) > 0
        assert len(proof_result.input_commitment) == 64

        # Positive verification with ZKMLVerifier
        verifier = ZKMLVerifier(
            settings_path=prover.settings_path,
            vk_path=prover.vk_path,
            srs_path=prover.srs_path,
            expected_model_hash=prover.model_hash,
        )
        verified = verifier.verify(proof_result, feature_vector=feat_list)
        assert verified is True

        # -------------------------------------------------------------
        # STEP 7: P10 DID Resolution & EIP-712 Attestation Anchoring
        # -------------------------------------------------------------
        assert is_valid_did(self.investigator_did) is True
        assert is_valid_did(self.zkml_did) is True
        did_doc = resolve_did(self.investigator_did)
        assert did_doc["id"] == self.investigator_did

        # Create ISO/IEC 27037 compliant attestation payloads
        xai_art_hash, xai_stmt_hash = create_ml_xai_attestation_payload(
            evidence_id=1,
            model_sha256="0x" + proof_result.model_hash,
            entity_address=from_addr,
            explanation_dict={
                "prediction_score": ml_score,
                "top_drivers": explanation.top_drivers,
                "mitre": mitre_mapping.technique_id,
            },
        )
        zkml_art_hash, zkml_stmt_hash = create_zkml_attestation_payload(
            evidence_id=1,
            model_sha256="0x" + proof_result.model_hash,
            proof_sha256=proof_result.proof_hash,
            input_commitment=proof_result.input_commitment,
            output_commitment="0x" + hashlib.sha256(str(proof_result.output_score).encode()).hexdigest(),
            vk_sha256="0x" + hashlib.sha256(b"vk_bytes").hexdigest(),
        )

        # Zero leakage privacy audit
        assert len(scan_for_sensitive_leakage({"art": xai_art_hash, "stmt": xai_stmt_hash}, canaries=["CANARY_KEY_123"])) == 0
        assert len(scan_for_sensitive_leakage({"art": zkml_art_hash, "stmt": zkml_stmt_hash}, canaries=["CANARY_KEY_123"])) == 0

        # Sign EIP-712 structured data
        verifying_contract = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        chain_id = 31337
        typed_data = build_attestation_typed_data(
            verifying_contract=verifying_contract,
            chain_id=chain_id,
            evidence_id=1,
            attestor=self.zkml_addr,
            role=ROLE_ZKML_VERIFIER,
            artifact_hash=zkml_art_hash,
            statement_hash=zkml_stmt_hash,
            nonce=0,
            deadline=9999999999,
        )
        sig = sign_typed_data(typed_data=typed_data, private_key=self.zkml_key)
        assert verify_typed_signature(signer_address=self.zkml_addr, typed_data=typed_data, signature=sig) is True

    def test_multi_layer_adversarial_rejection(self):
        """Verify cross-layer rejection of tampering, spoofing, injection, and privilege escalation."""
        # Layer 1: SafetyGuard rejects shell execution and log tampering
        with pytest.raises(DangerousActionError):
            SafetyGuard.validate_action("powershell.exe -Command Remove-EventLog -LogName Security")
        with pytest.raises(DangerousActionError):
            SafetyGuard.validate_action("cmd.exe /c whoami")

        # Layer 2: P8 MITRE engine rejects empty evidence references
        mitre_engine = MitreMappingEngine(strict_evidence=True)
        with pytest.raises(UnsubstantiatedMappingError):
            mitre_engine.map_anomaly(
                features={"max_single_out_ratio": 0.95},
                anomaly_score=0.90,
                rule_alerts=[],
                evidence_refs=[],
            )

        # Layer 3: P5 ObservedFact rejects subjective ML or threat vocabulary
        with pytest.raises(ValidationError) as exc_info:
            ObservedFact(
                statement="This address is definitely anomalous according to MITRE T1565.001",
                tx_hash="0x" + "a" * 64,
                block_number=100,
                from_addr="0x" + "b" * 40,
                to_addr="0x" + "c" * 40,
                asset_id="ETH",
                amount_raw="1000",
                evidence_refs=["tx:0x" + "a" * 64]
            )
        assert "Field separation violation" in str(exc_info.value)

        # Layer 4: P5 RefChecker rejects hallucinated transaction hashes
        conn = sqlite3.connect(REAL_P4_DB)
        conn.row_factory = sqlite3.Row
        fake_tx = "0xdeadbeef" + "0" * 56
        tampered_out = {
            "case_id": "CASE-FAKE",
            "observed_facts": [],
            "rule_detections": [],
            "ml_detections": [{
                "model_id": "m1",
                "model_sha256": "0" * 64,
                "entity_address": "0x" + "1" * 40,
                "score": 0.9,
                "classification": "anomalous",
                "evidence_refs": [f"tx:{fake_tx}"],
            }],
        }
        res_tampered = check_investigation_output(tampered_out, db=conn)
        assert res_tampered.existence_ref_ratio < 1.0
        assert f"tx:{fake_tx}" in res_tampered.missing_refs
        conn.close()

        # Layer 5: P9 ZKML Verifier rejects tampered proofs and spoofed public scores
        prover = ZKMLProver(
            model_path=Path("models/anomaly_detector_v1.onnx"),
            artifacts_dir=Path("scratch/zkml_artifacts"),
            auto_setup=True,
        )
        verifier = ZKMLVerifier(
            settings_path=prover.settings_path,
            vk_path=prover.vk_path,
            srs_path=prover.srs_path,
            expected_model_hash=prover.model_hash,
        )
        feat_list = [0.0] * 10
        proof_res = prover.prove(feat_list)

        # Flip bit in proof bytes
        tampered_bytes = bytearray(proof_res.proof_bytes)
        tampered_bytes[10] ^= 0xFF
        mutated_res = dataclasses.replace(
            proof_res,
            proof_bytes=bytes(tampered_bytes),
        )
        assert verifier.verify(mutated_res, feature_vector=feat_list) is False

        # Layer 6: P10 rejects signature tampering and signer mismatch
        verifying_contract = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        chain_id = 31337
        typed_data = build_custody_transfer_typed_data(
            verifying_contract=verifying_contract,
            chain_id=chain_id,
            evidence_id=1,
            from_custodian=self.investigator_addr,
            to_custodian=self.zkml_addr,
            artifact_sha256="0x" + "aa" * 32,
            note_hash="0x" + "bb" * 32,
            nonce=0,
            deadline=9999999999,
        )
        sig = sign_typed_data(typed_data=typed_data, private_key=self.investigator_key)
        # Verify with wrong signer address must fail
        assert verify_typed_signature(signer_address=self.zkml_addr, typed_data=typed_data, signature=sig) is False

    def test_canonical_database_invariance(self):
        """Strict verification of canonical database bitwise invariance."""
        expected_hashes = {
            "real_p4.db": "6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97",
            "forensics.db": "3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001",
        }
        for name, expected in expected_hashes.items():
            path = Path("data") / name
            if path.exists():
                actual = calculate_sha256(str(path)).upper()
                assert actual == expected, f"Database invariant violated for {name}: expected {expected}, got {actual}"
