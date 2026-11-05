"""Portable paths; never depend on the author's drive or current directory."""
import hashlib
import os
from pathlib import Path
import shutil

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get('FORENSICS_DATA_DIR', str(PROJECT_ROOT / 'data'))).resolve()
DATASETS_DIR = PROJECT_ROOT / 'datasets'
TOOLS_DIR = PROJECT_ROOT / 'tools'
CIRCUITS_DIR = PROJECT_ROOT / 'circuits'
MODELS_DIR = PROJECT_ROOT / 'models'
REAL_P4_DB = DATA_DIR / 'real_p4.db'
BENCHMARK_DB = DATA_DIR / 'benchmark_p6.db'
FORENSICS_DB = DATA_DIR / 'forensics.db'
ENDPOINT_EVIDENCE_DB = Path(os.environ.get("ENDPOINT_EVIDENCE_DB", str(DATA_DIR / "endpoint_evidence.db"))).resolve()


def get_project_root() -> Path:
    return PROJECT_ROOT


def get_data_dir() -> Path:
    return Path(os.environ.get('FORENSICS_DATA_DIR', str(PROJECT_ROOT / 'data'))).resolve()


def get_tools_dir() -> Path:
    return PROJECT_ROOT / 'tools'


def get_circuits_dir() -> Path:
    return CIRCUITS_DIR


def get_models_dir() -> Path:
    return MODELS_DIR


CANONICAL_ENV_SHA256 = "C2F4879666CD21276C58EC75DE923C8235D414F3D646A854A835C5638EC1699C"


def accepted_env_sha256(root: Path | str | None = None) -> set[str]:
    """The source .env holds live keys and is never distributed; a portable
    install seeds .env from .env.example, so both digests are legitimate."""
    base = Path(root) if root else PROJECT_ROOT
    accepted = {CANONICAL_ENV_SHA256}
    example = base / '.env.example'
    if example.is_file():
        accepted.add(hashlib.sha256(example.read_bytes()).hexdigest().upper())
    return accepted


def resolve_foundry_binary(name: str) -> str:
    """Prefer bundled tools/foundry binaries so execution works without host Foundry installs."""
    clean = name[:-4] if name.lower().endswith('.exe') else name
    for candidate in (
        TOOLS_DIR / 'foundry' / f'{clean}.exe',
        TOOLS_DIR / 'foundry' / clean,
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


def get_forensics_db() -> Path:
    return FORENSICS_DB


def get_real_p4_db() -> Path:
    return REAL_P4_DB


def get_benchmark_db() -> Path:
    return BENCHMARK_DB


def get_endpoint_evidence_db() -> Path:
    return Path(os.environ.get("ENDPOINT_EVIDENCE_DB", str(DATA_DIR / "endpoint_evidence.db"))).resolve()
