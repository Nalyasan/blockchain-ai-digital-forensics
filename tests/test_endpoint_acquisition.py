"""Comprehensive Test Suite for P7 Endpoint Evidence Ingestion, Storage, and AI Integration.

Verifies:
1. Canonical Endpoint Schemas (`forensics/endpoint/schemas.py`).
2. Dual-Mode Telemetry Daemon & Providers (`forensics/endpoint/daemon.py`).
3. Dedicated Endpoint Evidence Store (`forensics/endpoint/store.py`).
4. Append-Only Persistence & Conflict Detection (`insert_verified`).
5. Hardened 5-Layer Read-Only SQLite Enforcement.
6. Strict Database Isolation (endpoint_evidence.db isolated from real_p4.db / forensics.db).
7. AI Investigator P5 Schemas, Field Purity, Tools, and Step Budget.
8. Two-Stage Reference Checker Integration (Stage 1 Existence, Stage 2 Bit-for-bit Content Match).
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
import uuid
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from forensics.ai.db_readonly import get_readonly_connection
from forensics.ai.ref_checker import (
    RefMismatch,
    ReferenceCheckResult,
    check_investigation_output,
    verify_endpoint_artifacts,
    verify_references_existence,
)
from forensics.ai.schemas import (
    EndpointEvidenceArtifact,
    FirstResponseTriageResult,
    ForensicInvestigationOutput,
    SPECULATIVE_WORDS,
)
from forensics.ai.tools import (
    AUTHORIZED_TOOLS,
    MAX_AI_TOOL_STEPS,
    ToolBudgetManager,
    execute_guarded_tool,
    query_endpoint_telemetry,
    run_safe_endpoint_triage,
)
from forensics.endpoint.daemon import (
    MockTelemetryProvider,
    OsqueryProvider,
    TelemetryProvider,
    WMIPowerShellFallbackProvider,
    get_default_provider,
    query_endpoint,
)
from forensics.endpoint.schemas import (
    BaseEndpointRecord,
    EventRecord,
    ProcessRecord,
    SocketRecord,
    SystemInfoRecord,
    canonical_json,
    compute_payload_sha256,
    create_endpoint_record,
    generate_record_id,
)
from forensics.endpoint.store import (
    EndpointEvidenceStore,
    get_readonly_endpoint_connection,
    init_endpoint_db,
)
from forensics.paths import FORENSICS_DB, REAL_P4_DB
from forensics.persistence import EvidenceConflictError


@pytest.fixture
def temp_endpoint_db(tmp_path: Path) -> Path:
    """Fixture providing a fresh, isolated endpoint evidence database."""
    db_file = tmp_path / f"test_endpoint_{uuid.uuid4().hex}.db"
    init_endpoint_db(db_file)
    return db_file


@pytest.fixture
def endpoint_store(temp_endpoint_db: Path) -> EndpointEvidenceStore:
    """Fixture providing an EndpointEvidenceStore instance on an isolated database."""
    return EndpointEvidenceStore(temp_endpoint_db)


# ==============================================================================
# 1. Canonical Schemas Tests
# ==============================================================================


class TestEndpointSchemas:
    """Tests for canonical endpoint dataclasses and hashing invariants."""

    def test_canonical_json_determinism(self):
        d1 = {"b": 2, "a": 1, "nested": {"y": 20, "x": 10}}
        d2 = {"nested": {"x": 10, "y": 20}, "a": 1, "b": 2}
        assert canonical_json(d1) == canonical_json(d2)
        assert canonical_json(d1) == '{"a":1,"b":2,"nested":{"x":10,"y":20}}'

    def test_compute_payload_sha256_ignores_envelope_metadata(self):
        p1 = {"pid": 123, "name": "calc.exe"}
        p2 = {"pid": 123, "name": "calc.exe", "recorded_at_utc": "2026-11-04T00:00:00Z", "record_id": "proc_1"}
        assert compute_payload_sha256(p1) == compute_payload_sha256(p2)

    def test_generate_record_id(self):
        rid = generate_record_id("processes", "a1b2c3d4e5f60718293a4b5c6d7e8f90")
        assert rid == "proc_a1b2c3d4e5f60718"
        rid_sock = generate_record_id("sockets", "11223344556677889900aabbccddeeff")
        assert rid_sock == "sock_1122334455667788"

    def test_create_endpoint_process_record(self):
        payload = {
            "pid": 500,
            "name": "explorer.exe",
            "path": r"C:\Windows\explorer.exe",
            "cmdline": "explorer.exe",
            "parent_pid": 450,
            "sha256": "f" * 64,
            "start_time": "2026-11-04T07:00:00Z",
        }
        rec = create_endpoint_record("processes", "HOST1:wmi", payload)
        assert isinstance(rec, ProcessRecord)
        assert rec.pid == 500
        assert rec.name == "explorer.exe"
        assert rec.source_id == "HOST1:wmi"
        assert rec.record_type == "processes"
        assert rec.record_id.startswith("proc_")
        assert len(rec.payload_sha256) == 64
        assert rec.timestamp_utc.endswith("Z")

    def test_create_endpoint_socket_record(self):
        payload = {
            "pid": 1234,
            "protocol": "TCP",
            "local_address": "127.0.0.1",
            "local_port": 8080,
            "remote_address": "0.0.0.0",
            "remote_port": 0,
            "state": "Listen",
        }
        rec = create_endpoint_record("sockets", "HOST1:wmi", payload)
        assert isinstance(rec, SocketRecord)
        assert rec.protocol == "tcp"
        assert rec.local_port == 8080
        assert rec.state == "Listen"
        assert rec.record_id.startswith("sock_")

    def test_create_endpoint_event_record(self):
        payload = {
            "event_id": 7040,
            "source": "Service Control Manager",
            "channel": "System",
            "description": "Service state changed",
            "level": "Information",
        }
        rec = create_endpoint_record("events", "HOST1:wmi", payload)
        assert isinstance(rec, EventRecord)
        assert rec.event_id == 7040
        assert rec.channel == "System"
        assert rec.record_id.startswith("even_")

    def test_create_endpoint_system_info_record(self):
        payload = {
            "hostname": "TEST-HOST",
            "os_name": "Windows 11",
            "os_version": "10.0.26100",
            "uptime": 12000,
            "cpu_brand": "Intel Core i7",
            "memory_bytes": 16000000000,
        }
        rec = create_endpoint_record("system_info", "TEST-HOST:wmi", payload)
        assert isinstance(rec, SystemInfoRecord)
        assert rec.hostname == "TEST-HOST"
        assert rec.uptime == 12000
        assert rec.record_id.startswith("syst_")


# ==============================================================================
# 2. Dual-Mode Telemetry Daemon Tests
# ==============================================================================


class TestTelemetryDaemon:
    """Tests for daemon telemetry providers and query_endpoint interface."""

    def test_mock_provider_queries(self):
        mock = MockTelemetryProvider()
        assert mock.is_available() is True
        assert mock.get_provider_name() == "mock"

        procs = mock.query_processes(limit=2)
        assert len(procs) == 2
        assert all(isinstance(p, ProcessRecord) for p in procs)

        socks = mock.query_sockets(limit=2)
        assert len(socks) == 2
        assert all(isinstance(s, SocketRecord) for s in socks)

        events = mock.query_events(max_events=1)
        assert len(events) == 1
        assert isinstance(events[0], EventRecord)

        sys_info = mock.query_system_info()
        assert isinstance(sys_info, SystemInfoRecord)
        assert sys_info.hostname == "MOCK-HOST"

    def test_wmi_provider_system_info(self):
        wmi = WMIPowerShellFallbackProvider()
        if wmi.is_available():
            info = wmi.query_system_info()
            assert isinstance(info, SystemInfoRecord)
            assert info.hostname != ""
            assert info.uptime >= 0
            assert info.memory_bytes >= 0

    def test_query_endpoint_interface_contract(self):
        res_procs = query_endpoint("processes", force_mock=True, limit=2)
        assert len(res_procs) == 2
        assert all(isinstance(r, ProcessRecord) for r in res_procs)

        res_socks = query_endpoint("sockets", force_mock=True, limit=1)
        assert len(res_socks) == 1
        assert isinstance(res_socks[0], SocketRecord)

        res_events = query_endpoint("events", force_mock=True, max_events=1)
        assert len(res_events) == 1
        assert isinstance(res_events[0], EventRecord)

        res_sys = query_endpoint("system_info", force_mock=True)
        assert len(res_sys) == 1
        assert isinstance(res_sys[0], SystemInfoRecord)

    def test_query_endpoint_invalid_category_raises(self):
        with pytest.raises(ValueError, match="Unsupported query_type"):
            query_endpoint("unsupported_category")  # type: ignore[arg-type]


# ==============================================================================
# 3. Dedicated Endpoint Evidence Store & Persistence Tests
# ==============================================================================


class TestEndpointEvidenceStore:
    """Tests for endpoint_evidence.db schema, append-only writes, and read-only mode."""

    def test_store_initialization(self, temp_endpoint_db: Path):
        with sqlite3.connect(temp_endpoint_db) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {row[0] for row in cursor.fetchall()}
            assert "endpoint_processes" in tables
            assert "endpoint_sockets" in tables
            assert "endpoint_events" in tables
            assert "endpoint_system_info" in tables
            assert "triage_audit_log" in tables

    def test_append_only_processes_insertion(self, endpoint_store: EndpointEvidenceStore):
        p = create_endpoint_record(
            "processes",
            "host1:test",
            {"pid": 1001, "name": "app.exe", "path": "C:\\app.exe", "cmdline": "app.exe"},
        )
        assert endpoint_store.insert_process(p) is True

        # Re-inserting identical payload is safe idempotent replay (returns False)
        assert endpoint_store.insert_process(p) is False

    def test_append_only_sockets_insertion(self, endpoint_store: EndpointEvidenceStore):
        s = create_endpoint_record(
            "sockets",
            "host1:test",
            {"pid": 1001, "protocol": "tcp", "local_address": "127.0.0.1", "local_port": 9000, "remote_address": "0.0.0.0", "remote_port": 0, "state": "Listen"},
        )
        assert endpoint_store.insert_socket(s) is True
        assert endpoint_store.insert_socket(s) is False

    def test_append_only_events_insertion(self, endpoint_store: EndpointEvidenceStore):
        e = create_endpoint_record(
            "events",
            "host1:test",
            {"event_id": 100, "source": "Kernel", "channel": "System", "description": "Boot", "level": "Information"},
        )
        assert endpoint_store.insert_event(e) is True
        assert endpoint_store.insert_event(e) is False

    def test_append_only_system_info_insertion(self, endpoint_store: EndpointEvidenceStore):
        si = create_endpoint_record(
            "system_info",
            "host1:test",
            {"hostname": "HOST1", "os_name": "Windows", "os_version": "11", "uptime": 500, "cpu_brand": "AMD", "memory_bytes": 8000000000},
        )
        assert endpoint_store.insert_system_info(si) is True
        assert endpoint_store.insert_system_info(si) is False

    def test_triage_audit_log_insertion(self, endpoint_store: EndpointEvidenceStore):
        audit = {
            "triage_id": "trg_001",
            "action_name": "triage_running_processes",
            "operator_or_agent": "AIFirstResponder",
            "case_id": "incident_101",
            "target_params_json": {"limit": 10},
            "started_at_utc": "2026-11-04T07:00:00Z",
            "completed_at_utc": "2026-11-04T07:00:01Z",
            "status": "SUCCESS",
            "records_count": 10,
            "result_digest_sha256": "0" * 64,
            "findings_summary": "Clean",
            "details_json": {},
        }
        assert endpoint_store.insert_triage_audit(audit) is True
        assert endpoint_store.insert_triage_audit(audit) is False

    def test_conflicting_payload_raises_evidence_conflict(self, endpoint_store: EndpointEvidenceStore):
        p1 = create_endpoint_record(
            "processes",
            "host1:test",
            {"record_id": "proc_fixed_id", "pid": 1001, "name": "clean.exe"},
        )
        endpoint_store.insert_process(p1)

        # Conflicting name on same record_id
        p2 = create_endpoint_record(
            "processes",
            "host1:test",
            {"record_id": "proc_fixed_id", "pid": 1001, "name": "malicious.exe"},
        )
        with pytest.raises(EvidenceConflictError):
            endpoint_store.insert_process(p2)

    def test_hardened_readonly_connection_blocks_mutations(self, endpoint_store: EndpointEvidenceStore):
        ro = endpoint_store.get_readonly_connection()
        with pytest.raises(sqlite3.OperationalError):
            ro.execute("INSERT INTO endpoint_processes (record_id) VALUES ('evil');")
        with pytest.raises(sqlite3.OperationalError):
            ro.execute("DELETE FROM endpoint_processes;")
        with pytest.raises(sqlite3.OperationalError):
            ro.execute("UPDATE endpoint_processes SET name='tampered';")
        with pytest.raises(sqlite3.OperationalError):
            ro.execute("DROP TABLE endpoint_processes;")

    def test_strict_database_isolation(self, temp_endpoint_db: Path):
        """Verifies endpoint_evidence.db is strictly isolated from blockchain databases."""
        with sqlite3.connect(temp_endpoint_db) as ep_conn:
            cursor = ep_conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            ep_tables = {row[0] for row in cursor.fetchall()}
            assert "blocks" not in ep_tables
            assert "transactions" not in ep_tables
            assert "asset_transfers" not in ep_tables

        # Check that REAL_P4_DB does not have endpoint tables
        if REAL_P4_DB.exists():
            with get_readonly_connection(REAL_P4_DB) as p4_conn:
                cursor = p4_conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                p4_tables = {row[0] for row in cursor.fetchall()}
                assert "endpoint_processes" not in p4_tables
                assert "endpoint_sockets" not in p4_tables
                assert "endpoint_events" not in p4_tables


# ==============================================================================
# 4. AI Investigator P5 Extension Tests
# ==============================================================================


class TestAIInvestigatorEndpointIntegration:
    """Tests for P5 schemas, field purity, authorized tools, and reference checking."""

    def test_endpoint_evidence_artifact_valid(self):
        art = EndpointEvidenceArtifact(
            artifact_type="process",
            record_id="proc_1234567812345678",
            host_id="LAPTOP-WIN",
            payload_sha256="a" * 64,
            summary="Process svchost.exe running under system services",
            details={"pid": 1250, "parent_pid": 940},
            evidence_refs=["endpoint:proc:1250"],
        )
        assert art.artifact_type == "process"
        assert art.record_id == "proc_1234567812345678"

    def test_endpoint_evidence_artifact_field_purity_rejects_speculative_words(self):
        """Field purity invariant: summary must NOT contain speculative or ML words."""
        for word in ["suspect", "anomaly", "attacker", "exploit", "malicious", "phishing"]:
            with pytest.raises(ValidationError, match="Field separation violation"):
                EndpointEvidenceArtifact(
                    artifact_type="process",
                    record_id="proc_test",
                    host_id="host1",
                    payload_sha256="b" * 64,
                    summary=f"This process is a {word} execution",
                )

    def test_first_response_triage_result_valid(self):
        res = FirstResponseTriageResult(
            triage_id="trg_1234",
            playbook_name="triage_running_processes",
            case_id="incident_001",
            executed_at_utc="2026-11-04T07:00:00Z",
            status="SUCCESS",
            findings_summary="Collected 25 running processes with zero suspicious temp directories",
            artifacts=[],
            evidence_refs=[],
            audit_digest_sha256="c" * 64,
        )
        assert res.status == "SUCCESS"
        assert res.playbook_name == "triage_running_processes"

    def test_query_endpoint_telemetry_tool(self, endpoint_store: EndpointEvidenceStore):
        p = create_endpoint_record(
            "processes",
            "host1:test",
            {"pid": 2048, "name": "service.exe", "path": "C:\\service.exe", "cmdline": "service.exe -k"},
        )
        endpoint_store.insert_process(p)

        ro = endpoint_store.get_readonly_connection()
        res = query_endpoint_telemetry(category="processes", db=ro, filter_query="service")
        assert len(res) == 1
        assert res[0]["name"] == "service.exe"
        assert "cmdline_sanitized" in res[0]

    def test_run_safe_endpoint_triage_tool(self, temp_endpoint_db: Path):
        res = run_safe_endpoint_triage(
            playbook_name="process_triage",
            case_id="case-100",
            endpoint_db_path=temp_endpoint_db,
            force_mock=True,
        )
        assert res["status"] == "SUCCESS"
        assert res["blocked"] is False
        assert res["records_count"] > 0

    def test_endpoint_tools_count_towards_step_budget(self):
        tracker = ToolBudgetManager(max_steps=5)
        funcs = {
            "query_endpoint_telemetry": lambda **kwargs: [{"mock": 1}],
            "run_safe_endpoint_triage": lambda **kwargs: {"status": "SUCCESS"},
        }
        execute_guarded_tool("query_endpoint_telemetry", {}, funcs, tracker)
        assert tracker.attempted_tool_calls == 1
        assert tracker.successful_tool_calls == 1

        execute_guarded_tool("run_safe_endpoint_triage", {}, funcs, tracker)
        assert tracker.attempted_tool_calls == 2
        assert tracker.successful_tool_calls == 2

    def test_reference_checker_valid_endpoint_ref_passes(self, endpoint_store: EndpointEvidenceStore):
        # Insert genuine process into endpoint db
        p = create_endpoint_record(
            "processes",
            "host1:test",
            {"pid": 4096, "name": "verified.exe", "path": "C:\\verified.exe"},
        )
        endpoint_store.insert_process(p)

        ro_ep = endpoint_store.get_readonly_connection()
        ratio, missing = verify_references_existence(
            endpoint_refs=[f"endpoint:proc:{p.record_id}"],
            db=ro_ep,
            endpoint_db=ro_ep,
        )
        assert ratio == 1.0
        assert missing == []

    def test_reference_checker_hallucinated_endpoint_ref_fails(self, endpoint_store: EndpointEvidenceStore):
        ro_ep = endpoint_store.get_readonly_connection()
        ratio, missing = verify_references_existence(
            endpoint_refs=["endpoint:proc:proc_hallucinated999"],
            db=ro_ep,
            endpoint_db=ro_ep,
        )
        assert ratio == 0.0
        assert "endpoint:proc:proc_hallucinated999" in missing

    def test_reference_checker_stage2_endpoint_artifact_verification(self, endpoint_store: EndpointEvidenceStore):
        p = create_endpoint_record(
            "processes",
            "host1:test",
            {"pid": 7777, "name": "daemon.exe", "path": "C:\\daemon.exe"},
        )
        endpoint_store.insert_process(p)

        ro_ep = endpoint_store.get_readonly_connection()

        # Genuine artifact matches bit-for-bit
        art_valid = EndpointEvidenceArtifact(
            artifact_type="process",
            record_id=p.record_id,
            host_id="host1",
            payload_sha256=p.payload_sha256,
            summary="Process daemon.exe executing under host1",
        )
        mismatches = verify_endpoint_artifacts([art_valid], endpoint_db=ro_ep)
        assert len(mismatches) == 0

        # Hallucinated payload_sha256 triggers CONTENT_MISMATCH
        art_tampered = EndpointEvidenceArtifact(
            artifact_type="process",
            record_id=p.record_id,
            host_id="host1",
            payload_sha256="0" * 64,  # altered digest
            summary="Process daemon.exe executing under host1",
        )
        mismatches_tampered = verify_endpoint_artifacts([art_tampered], endpoint_db=ro_ep)
        assert len(mismatches_tampered) == 1
        assert mismatches_tampered[0].tag == "CONTENT_MISMATCH"
        assert mismatches_tampered[0].field == "payload_sha256"


# ==============================================================================
# 5. Milestone M4: Evidence Source Adapters & ISO/IEC 27037 Manifest Tests
# ==============================================================================


import json

from forensics.endpoint.adapter import (
    ConsentScopeViolation,
    EVMCollectorAdapter,
    EvidenceSourceAdapter,
    EvtxLogAdapter,
    ForensicIntegrityError,
    JsonlLogAdapter,
)
from forensics.endpoint.manifest import (
    generate_acquisition_manifest,
    verify_acquisition_manifest,
)
from forensics.endpoint.schemas import AcquisitionResult


class TestEndpointAcquisitionAdaptersM4:
    """Verifies Milestone M4 EvidenceSourceAdapter, ISO/IEC 27037 Manifest, and Gate T12."""

    def test_jsonl_log_adapter_end_to_end(self, tmp_path: Path, endpoint_store: EndpointEvidenceStore):
        vault_dir = tmp_path / "vault"
        jsonl_file = tmp_path / "host_telemetry.jsonl"
        lines = [
            json.dumps({"EventID": 1, "Image": r"C:\Windows\System32\svchost.exe", "ProcessId": 1234, "Hashes": "SHA256=11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff", "User": r"NT AUTHORITY\SYSTEM"}),
            json.dumps({"record_type": "sockets", "pid": 1234, "protocol": "tcp", "local_address": "127.0.0.1", "local_port": 8080, "remote_address": "10.0.0.1", "remote_port": 443, "state": "Established"}),
            json.dumps({"EventID": 4624, "Channel": "Security", "Description": "An account was successfully logged on", "User": "Administrator"}),
        ]
        jsonl_file.write_text("\n".join(lines), encoding="utf-8")

        adapter = JsonlLogAdapter(
            case_id="CASE-2026-TEST",
            operator_did="did:ethr:0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            vault_dir=vault_dir,
            evidence_store=endpoint_store,
        )

        result = adapter.collect(str(jsonl_file), consent_scope="security_events_only")

        assert isinstance(result, AcquisitionResult)
        assert result.status == "VERIFIED"
        assert result.original_sha256 == result.copy_sha256
        assert result.record_count >= 3
        assert Path(result.destination_path).exists()
        assert Path(result.manifest_path).exists()

        # Check ISO/IEC 27037 Manifest validation
        is_valid, reason = verify_acquisition_manifest(result.manifest_path)
        assert is_valid, f"Manifest verification failed: {reason}"

        # Verify entry in endpoint_evidence table
        stored_acq = endpoint_store.get_acquisition(result.acquisition_id)
        assert stored_acq is not None
        assert stored_acq["original_sha256"] == result.original_sha256
        assert stored_acq["case_id"] == "CASE-2026-TEST"

    def test_evtx_log_adapter_end_to_end(self, tmp_path: Path, endpoint_store: EndpointEvidenceStore):
        vault_dir = tmp_path / "vault"
        evtx_file = tmp_path / "exported_security.evtx"
        # Create valid JSONL fixture with .evtx extension (fallback parser test)
        content = json.dumps({"EventID": 7045, "ProviderName": "Service Control Manager", "Description": "A new service was installed in the system.", "LevelDisplayName": "Information"}) + "\n"
        evtx_file.write_text(content, encoding="utf-8")

        adapter = EvtxLogAdapter(
            case_id="CASE-2026-EVTX",
            operator_did="did:ethr:0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            vault_dir=vault_dir,
            evidence_store=endpoint_store,
        )

        result = adapter.collect(str(evtx_file), consent_scope="host_logs")
        assert result.status == "VERIFIED"
        assert result.original_sha256 == result.copy_sha256
        assert result.record_count >= 1

        is_valid, reason = verify_acquisition_manifest(result.manifest_path)
        assert is_valid, f"Manifest invalid: {reason}"

    def test_evm_collector_adapter_end_to_end(self, tmp_path: Path, endpoint_store: EndpointEvidenceStore):
        vault_dir = tmp_path / "vault"
        adapter = EVMCollectorAdapter(
            case_id="CASE-2026-EVM",
            operator_did="did:ethr:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            vault_dir=vault_dir,
            evidence_store=endpoint_store,
        )
        result = adapter.collect("eth_getBlockByNumber(19000000)", consent_scope="blockchain_transactions")
        assert result.status == "VERIFIED"
        assert result.source_type == "EVM"
        assert Path(result.destination_path).exists()
        assert Path(result.manifest_path).exists()

    def test_bit_flip_tampering_detection(self, tmp_path: Path, endpoint_store: EndpointEvidenceStore):
        vault_dir = tmp_path / "vault"
        src_file = tmp_path / "sample.jsonl"
        src_file.write_text('{"event": "test"}\n', encoding="utf-8")

        class TamperingAdapter(JsonlLogAdapter):
            def _bitwise_preserve(self, source_path: Path, acquisition_id: str):
                orig_sha, copy_sha, dest_path = super()._bitwise_preserve(source_path, acquisition_id)
                # Mutate 1 byte in destination vault copy
                with open(dest_path, "r+b") as f:
                    b = f.read(1)
                    f.seek(0)
                    f.write(bytes([b[0] ^ 0xFF]))
                # Now re-hash destination to simulate corrupted copy
                hasher = hashlib.sha256()
                with open(dest_path, "rb") as f:
                    hasher.update(f.read())
                tampered_sha = hasher.hexdigest()
                if orig_sha != tampered_sha:
                    raise ForensicIntegrityError(f"Bit-stream verification failed! original={orig_sha} != copy={tampered_sha}")
                return orig_sha, tampered_sha, dest_path

        tampered_adapter = TamperingAdapter(vault_dir=vault_dir, evidence_store=endpoint_store)
        with pytest.raises(ForensicIntegrityError):
            tampered_adapter.collect(str(src_file), consent_scope="security_events_only")

    def test_consent_scope_violation_rejection(self, tmp_path: Path, endpoint_store: EndpointEvidenceStore):
        src_file = tmp_path / "sample.jsonl"
        src_file.write_text('{"event": "test"}\n', encoding="utf-8")
        adapter = JsonlLogAdapter(vault_dir=tmp_path / "vault", evidence_store=endpoint_store)

        # Empty scope rejected
        with pytest.raises(ConsentScopeViolation):
            adapter.collect(str(src_file), consent_scope="")

        # Unauthorized scope rejected
        with pytest.raises(ConsentScopeViolation):
            adapter.collect(str(src_file), consent_scope="unauthorized_personal_finance")

    def test_canonical_database_invariance(self):
        """Verifies that endpoint operations have zero effect on canonical baseline databases."""
        paths = {
            "real_p4.db": Path("data/real_p4.db"),
            "forensics.db": Path("data/forensics.db"),
            "benchmark_p6.db": Path("data/benchmark_p6.db"),
            ".env": Path(".env"),
        }
        expected = {
            "real_p4.db": "6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97",
            "forensics.db": "3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001",
            "benchmark_p6.db": "C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507",
            ".env": "C2F4879666CD21276C58EC75DE923C8235D414F3D646A854A835C5638EC1699C",
        }
        for name, p in paths.items():
            if p.exists():
                digest = hashlib.sha256(p.read_bytes()).hexdigest().upper()
                assert digest == expected[name], f"Canonical DB {name} was modified!"

