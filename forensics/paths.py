"""Portable paths; never depend on the author's drive or current directory.

Centralized Path Anchor & Discovery adhering to AGENT.md v6.1 and R2/R5.
Provides dynamic repository root detection via root markers (AGENT.md, .git),
parent traversal fallback, full CLI/environment variable parameterization,
and session-isolated output paths.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
from typing import Optional, Set


def find_project_root(start_path: Path | str | None = None) -> Path:
    """Dynamically detect repository root using root markers (AGENT.md, .git),
    with fallback to parent traversal, zero dependency on CWD or hardcoded paths.
    Respects PROJECT_ROOT environment variable if set and valid.
    """
    env_root = os.environ.get("PROJECT_ROOT")
    if env_root:
        p = Path(env_root).resolve()
        if p.is_dir():
            return p

    start = Path(start_path).resolve() if start_path else Path(__file__).resolve().parent
    for current in [start] + list(start.parents):
        if (current / "AGENT.md").is_file() or (current / ".git").exists():
            return current

    # Fallback to parent of forensics package
    return Path(__file__).resolve().parents[1]


# Dynamic module-level root anchor
PROJECT_ROOT = find_project_root()


def get_project_root() -> Path:
    """Return dynamically detected repository root."""
    return find_project_root()


def get_data_dir() -> Path:
    """Return data directory, respecting FORENSICS_DATA_DIR or DATA_DIR env vars."""
    env_dir = os.environ.get("FORENSICS_DATA_DIR") or os.environ.get("DATA_DIR")
    if env_dir:
        return Path(env_dir).resolve()
    return (get_project_root() / "data").resolve()


def get_models_dir() -> Path:
    """Return models directory, respecting MODELS_DIR or MODEL_PATH env vars."""
    env_dir = os.environ.get("MODELS_DIR")
    if env_dir:
        return Path(env_dir).resolve()
    model_env = os.environ.get("MODEL_PATH")
    if model_env:
        p = Path(model_env).resolve()
        return p if p.is_dir() else p.parent
    return (get_project_root() / "models").resolve()


def get_circuits_dir() -> Path:
    """Return circuits directory, respecting CIRCUITS_DIR env var."""
    env_dir = os.environ.get("CIRCUITS_DIR")
    if env_dir:
        return Path(env_dir).resolve()
    return (get_project_root() / "circuits").resolve()


def get_reports_dir() -> Path:
    """Return reports directory, respecting REPORTS_DIR or OUTPUT_DIR env vars."""
    env_dir = os.environ.get("REPORTS_DIR")
    if env_dir:
        return Path(env_dir).resolve()
    return (get_project_root() / "reports").resolve()


def get_tools_dir() -> Path:
    """Return tools directory, respecting TOOLS_DIR env var."""
    env_dir = os.environ.get("TOOLS_DIR")
    if env_dir:
        return Path(env_dir).resolve()
    return (get_project_root() / "tools").resolve()


def get_datasets_dir() -> Path:
    """Return datasets directory."""
    return (get_project_root() / "datasets").resolve()


# Core Database Getters
def get_forensics_db() -> Path:
    """Return canonical or configured forensics database path."""
    return (get_data_dir() / "forensics.db").resolve()


def get_real_p4_db() -> Path:
    """Return canonical real P4 ground truth database path."""
    return (get_data_dir() / "real_p4.db").resolve()


def get_benchmark_db() -> Path:
    """Return canonical benchmark P6 database path."""
    return (get_data_dir() / "benchmark_p6.db").resolve()


def get_endpoint_evidence_db() -> Path:
    """Return canonical or configured endpoint evidence database path."""
    env_db = os.environ.get("ENDPOINT_EVIDENCE_DB") or os.environ.get("EVIDENCE_PATH")
    if env_db:
        p = Path(env_db)
        if not p.is_absolute():
            p = (get_project_root() / p).resolve()
        return p
    return (get_data_dir() / "endpoint_evidence.db").resolve()


# Environment & CLI Configuration Resolvers
def get_database_path() -> Path:
    """Resolve database path from DATABASE_PATH or DB_PATH, defaulting to forensics.db."""
    env_val = os.environ.get("DATABASE_PATH") or os.environ.get("DB_PATH")
    if env_val:
        p = Path(env_val)
        if not p.is_absolute():
            p = (get_project_root() / p).resolve()
        return p
    return get_forensics_db()


def get_model_path() -> Path:
    """Resolve model path from MODEL_PATH, defaulting to anomaly_detector_v1.onnx."""
    env_val = os.environ.get("MODEL_PATH")
    if env_val:
        p = Path(env_val)
        if not p.is_absolute():
            p = (get_project_root() / p).resolve()
        return p
    return (get_models_dir() / "anomaly_detector_v1.onnx").resolve()


def get_evidence_path() -> Path:
    """Resolve evidence database/vault path from EVIDENCE_PATH or ENDPOINT_EVIDENCE_DB."""
    return get_endpoint_evidence_db()


def get_output_dir() -> Path:
    """Resolve output directory from OUTPUT_DIR, defaulting to reports/investigations."""
    env_val = os.environ.get("OUTPUT_DIR")
    if env_val:
        p = Path(env_val)
        if not p.is_absolute():
            p = (get_project_root() / p).resolve()
        return p
    return (get_reports_dir() / "investigations").resolve()


def get_rpc_url() -> str:
    """Resolve RPC URL from RPC_URL or ANCHOR_RPC_URL, defaulting to local Anvil."""
    return os.environ.get("RPC_URL") or os.environ.get("ANCHOR_RPC_URL") or "http://127.0.0.1:8545"


def get_ollama_url() -> str:
    """Resolve Ollama URL from OLLAMA_URL or OLLAMA_BASE_URL, defaulting to local Ollama."""
    return os.environ.get("OLLAMA_URL") or os.environ.get("OLLAMA_BASE_URL") or "http://127.0.0.1:11434/v1"


def get_host() -> str:
    """Resolve HTTP server host from HOST, defaulting to 127.0.0.1."""
    return os.environ.get("HOST", "127.0.0.1")


def get_port() -> int:
    """Resolve HTTP server port from PORT, defaulting to 8000."""
    val = os.environ.get("PORT", "8000")
    try:
        return int(val)
    except ValueError:
        return 8000


def get_session_output_dir(run_id: str, base_dir: Path | str | None = None) -> Path:
    """Return dedicated session folder under reports/investigations/<run_id>/ without overwriting."""
    base = Path(base_dir).resolve() if base_dir else get_output_dir()
    session_dir = base / run_id
    session_dir.mkdir(parents=True, exist_ok=True)
    return session_dir


# Foundry Binary Resolution
def resolve_foundry_binary(name: str) -> str:
    """Prefer bundled tools/foundry binaries so execution works without host Foundry installs."""
    clean = name[:-4] if name.lower().endswith('.exe') else name
    tools_dir = get_tools_dir()
    for candidate in (
        tools_dir / 'foundry' / f'{clean}.exe',
        tools_dir / 'foundry' / clean,
    ):
        if candidate.is_file():
            return str(candidate.resolve())
    found = shutil.which(clean)
    if found:
        return found
    for candidate in (
        Path(os.path.expanduser(f'~/.foundry/bin/{clean}.exe')),
        Path(os.path.expanduser(f'~/.foundry/bin/{clean}')),
    ):
        if candidate.is_file():
            return str(candidate.resolve())
    return f'{clean}.exe' if os.name == 'nt' else clean


# Canonical Environment Invariance Check
CANONICAL_ENV_SHA256 = "C2F4879666CD21276C58EC75DE923C8235D414F3D646A854A835C5638EC1699C"


def accepted_env_sha256(root: Path | str | None = None) -> Set[str]:
    """The source .env holds live keys and is never distributed; a portable
    install seeds .env from .env.example, so both digests are legitimate."""
    base = Path(root) if root else get_project_root()
    accepted = {CANONICAL_ENV_SHA256}
    example = base / '.env.example'
    if example.is_file():
        accepted.add(hashlib.sha256(example.read_bytes()).hexdigest().upper())
    return accepted


# Backward-compatibility module aliases
DATA_DIR = get_data_dir()
DATASETS_DIR = get_datasets_dir()
TOOLS_DIR = get_tools_dir()
CIRCUITS_DIR = get_circuits_dir()
MODELS_DIR = get_models_dir()
REAL_P4_DB = get_real_p4_db()
BENCHMARK_DB = get_benchmark_db()
FORENSICS_DB = get_forensics_db()
ENDPOINT_EVIDENCE_DB = get_endpoint_evidence_db()
