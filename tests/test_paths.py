"""Unit & Cross-Platform Path Independence Tests (Milestone 2 / R2 / R5).

Validates:
1. Dynamic repository root detection via root markers (AGENT.md, .git).
2. Override of project root via PROJECT_ROOT environment variable.
3. Directory helper functions (data, models, circuits, reports, tools, datasets).
4. Full CLI and environment variable parameter resolution (9 parameters).
5. Session output isolation under reports/investigations/<run_id>/.
6. Foundry binary discovery across operating systems.
7. Execution invariance when CWD changes to outside directories.
8. Support for paths with spaces and Unicode characters on Windows.
"""
from __future__ import annotations

import os
from pathlib import Path
import pytest
import shutil
import tempfile

from forensics.paths import (
    find_project_root,
    get_project_root,
    get_data_dir,
    get_models_dir,
    get_circuits_dir,
    get_reports_dir,
    get_tools_dir,
    get_datasets_dir,
    get_forensics_db,
    get_real_p4_db,
    get_benchmark_db,
    get_endpoint_evidence_db,
    get_database_path,
    get_model_path,
    get_evidence_path,
    get_output_dir,
    get_rpc_url,
    get_ollama_url,
    get_host,
    get_port,
    get_session_output_dir,
    resolve_foundry_binary,
    PROJECT_ROOT,
)


class TestDynamicRootDetection:
    """Tests dynamic repository root detection with root markers and traversal."""

    def test_find_project_root_locates_agent_md_or_git(self):
        root = find_project_root()
        assert root.is_dir()
        assert (root / "AGENT.md").is_file() or (root / ".git").exists()

    def test_find_project_root_respects_env_var(self, tmp_path, monkeypatch):
        fake_root = tmp_path / "fake_repo"
        fake_root.mkdir()
        (fake_root / "AGENT.md").write_text("# Agent Spec", encoding="utf-8")
        monkeypatch.setenv("PROJECT_ROOT", str(fake_root))

        detected = find_project_root()
        assert detected == fake_root.resolve()

    def test_find_project_root_from_nested_subdirectory(self, tmp_path):
        repo = tmp_path / "deep_repo"
        repo.mkdir()
        (repo / "AGENT.md").write_text("# Spec", encoding="utf-8")
        nested = repo / "a" / "b" / "c" / "d"
        nested.mkdir(parents=True)

        detected = find_project_root(start_path=nested)
        assert detected == repo.resolve()


class TestDirectoryAndBinaryHelpers:
    """Tests directory getters and binary resolution."""

    def test_get_project_root_matches_module_constant(self):
        assert get_project_root().resolve() == PROJECT_ROOT.resolve()

    def test_get_data_dir(self, monkeypatch, tmp_path):
        default_data = get_data_dir()
        assert default_data == (PROJECT_ROOT / "data").resolve()

        custom = tmp_path / "custom_data"
        custom.mkdir()
        monkeypatch.setenv("FORENSICS_DATA_DIR", str(custom))
        assert get_data_dir() == custom.resolve()

    def test_get_models_dir(self, monkeypatch, tmp_path):
        default_models = get_models_dir()
        assert default_models == (PROJECT_ROOT / "models").resolve()

        custom = tmp_path / "custom_models"
        custom.mkdir()
        monkeypatch.setenv("MODELS_DIR", str(custom))
        assert get_models_dir() == custom.resolve()

    def test_get_circuits_dir(self, monkeypatch, tmp_path):
        default_circuits = get_circuits_dir()
        assert default_circuits == (PROJECT_ROOT / "circuits").resolve()

        custom = tmp_path / "custom_circuits"
        custom.mkdir()
        monkeypatch.setenv("CIRCUITS_DIR", str(custom))
        assert get_circuits_dir() == custom.resolve()

    def test_get_reports_dir(self, monkeypatch, tmp_path):
        default_reports = get_reports_dir()
        assert default_reports == (PROJECT_ROOT / "reports").resolve()

        custom = tmp_path / "custom_reports"
        custom.mkdir()
        monkeypatch.setenv("REPORTS_DIR", str(custom))
        assert get_reports_dir() == custom.resolve()

    def test_resolve_foundry_binary_finds_forge_and_cast(self):
        forge_bin = resolve_foundry_binary("forge")
        cast_bin = resolve_foundry_binary("cast")
        anvil_bin = resolve_foundry_binary("anvil")

        assert os.path.exists(forge_bin)
        assert os.path.exists(cast_bin)
        assert os.path.exists(anvil_bin)


class TestEnvironmentAndParameterResolution:
    """Tests the 9 required configuration parameters (R2/R5)."""

    def test_database_path_env_resolution(self, monkeypatch, tmp_path):
        custom_db = tmp_path / "custom_forensics.db"
        custom_db.touch()
        monkeypatch.setenv("DATABASE_PATH", str(custom_db))
        assert get_database_path() == custom_db.resolve()

        monkeypatch.delenv("DATABASE_PATH", raising=False)
        monkeypatch.setenv("DB_PATH", str(custom_db))
        assert get_database_path() == custom_db.resolve()

    def test_model_path_env_resolution(self, monkeypatch, tmp_path):
        custom_model = tmp_path / "custom_model.onnx"
        custom_model.touch()
        monkeypatch.setenv("MODEL_PATH", str(custom_model))
        assert get_model_path() == custom_model.resolve()

    def test_evidence_path_env_resolution(self, monkeypatch, tmp_path):
        custom_ev = tmp_path / "custom_ev.db"
        custom_ev.touch()
        monkeypatch.setenv("EVIDENCE_PATH", str(custom_ev))
        assert get_evidence_path() == custom_ev.resolve()

    def test_output_dir_env_resolution(self, monkeypatch, tmp_path):
        custom_out = tmp_path / "custom_out"
        custom_out.mkdir()
        monkeypatch.setenv("OUTPUT_DIR", str(custom_out))
        assert get_output_dir() == custom_out.resolve()

    def test_rpc_url_env_resolution(self, monkeypatch):
        custom_rpc = "http://127.0.0.1:9999"
        monkeypatch.setenv("RPC_URL", custom_rpc)
        assert get_rpc_url() == custom_rpc

    def test_ollama_url_env_resolution(self, monkeypatch):
        custom_ollama = "http://localhost:11434/v1"
        monkeypatch.setenv("OLLAMA_URL", custom_ollama)
        assert get_ollama_url() == custom_ollama

    def test_host_and_port_env_resolution(self, monkeypatch):
        monkeypatch.setenv("HOST", "0.0.0.0")
        monkeypatch.setenv("PORT", "9090")
        assert get_host() == "0.0.0.0"
        assert get_port() == 9090


class TestSessionOutputIsolation:
    """Tests session-isolated directory generation under reports/investigations/<run_id>/."""

    def test_session_output_dir_creates_isolated_folders(self, tmp_path):
        run1 = "run_case_1_20261107_120000"
        run2 = "run_case_1_20261107_120100"

        dir1 = get_session_output_dir(run1, base_dir=tmp_path)
        dir2 = get_session_output_dir(run2, base_dir=tmp_path)

        assert dir1.is_dir()
        assert dir2.is_dir()
        assert dir1 != dir2
        assert dir1.parent == dir2.parent == tmp_path.resolve()

        # Write data to dir1
        f1 = dir1 / "report.json"
        f1.write_text('{"run": 1}', encoding="utf-8")

        # Verify dir2 remains unaffected
        assert not (dir2 / "report.json").exists()


class TestCWDVarianceAndSpecialPaths:
    """Tests path independence when CWD varies, or paths contain spaces/Unicode."""

    def test_cwd_independence(self, tmp_path, monkeypatch):
        external_dir = tmp_path / "external_cwd"
        external_dir.mkdir()
        monkeypatch.chdir(external_dir)

        # Confirm CWD is external
        assert Path.cwd() == external_dir.resolve()

        # Dynamic root and core paths must still resolve to project repo, not external_dir
        assert get_project_root() == PROJECT_ROOT
        assert get_data_dir() == (PROJECT_ROOT / "data").resolve()
        assert get_forensics_db() == (PROJECT_ROOT / "data" / "forensics.db").resolve()
        assert get_real_p4_db() == (PROJECT_ROOT / "data" / "real_p4.db").resolve()
        assert Path(resolve_foundry_binary("forge")).is_file()

    def test_path_with_spaces(self, tmp_path):
        spaced_dir = tmp_path / "folder with spaces in name"
        spaced_dir.mkdir()
        session = get_session_output_dir("test_spaced_run", base_dir=spaced_dir)
        assert session.is_dir()
        test_file = session / "sample file.txt"
        test_file.write_text("forensic payload", encoding="utf-8")
        assert test_file.read_text(encoding="utf-8") == "forensic payload"

    def test_path_with_unicode(self, tmp_path):
        unicode_dir = tmp_path / "thư_mục_chứng_cứ_điều_tra"
        unicode_dir.mkdir()
        session = get_session_output_dir("phiên_điều_tra_01", base_dir=unicode_dir)
        assert session.is_dir()
        test_file = session / "báo_cáo_tiếng_việt.txt"
        test_file.write_text("Nội dung báo cáo điều tra pháp y", encoding="utf-8")
        assert test_file.read_text(encoding="utf-8") == "Nội dung báo cáo điều tra pháp y"

    def test_rule_engine_and_orchestrator_from_external_cwd(self, tmp_path, monkeypatch):
        external_dir = tmp_path / "outside_workspace"
        external_dir.mkdir()
        monkeypatch.chdir(external_dir)

        # Verify that get_forensics_db() and get_database_path() resolve to canonical project root
        from forensics.paths import get_forensics_db, get_database_path, get_real_p4_db, get_output_dir
        assert get_forensics_db() == (PROJECT_ROOT / "data" / "forensics.db").resolve()
        assert get_database_path() == (PROJECT_ROOT / "data" / "forensics.db").resolve()

        # RuleEngine initialized with an isolated database in external CWD
        from forensics.rules.engine import RuleEngine
        isolated_db = tmp_path / "test_engine.db"
        engine = RuleEngine(db_path_or_conn=str(isolated_db))
        try:
            assert engine.db_path == str(isolated_db.resolve())
        finally:
            engine.close()

        # CaseOrchestrator initialized with default real_p4.db from external CWD
        from investigate_case import CaseOrchestrator
        orchestrator = CaseOrchestrator(output_dir=tmp_path / "custom_reports")
        assert orchestrator.db_path == (PROJECT_ROOT / "data" / "real_p4.db").resolve()
        assert orchestrator.output_base == (tmp_path / "custom_reports").resolve()
        assert orchestrator.run_dir.is_dir()
