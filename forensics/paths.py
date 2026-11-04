"""Portable paths; never depend on the author's drive or current directory."""
import os
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get('FORENSICS_DATA_DIR', str(PROJECT_ROOT / 'data'))).resolve()
DATASETS_DIR = PROJECT_ROOT / 'datasets'
TOOLS_DIR = PROJECT_ROOT / 'tools'
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


def get_forensics_db() -> Path:
    return FORENSICS_DB


def get_real_p4_db() -> Path:
    return REAL_P4_DB


def get_benchmark_db() -> Path:
    return BENCHMARK_DB


def get_endpoint_evidence_db() -> Path:
    return Path(os.environ.get("ENDPOINT_EVIDENCE_DB", str(DATA_DIR / "endpoint_evidence.db"))).resolve()


