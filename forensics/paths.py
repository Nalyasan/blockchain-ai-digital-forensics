"""Portable paths; never depend on the author's drive or current directory."""
import os
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get('FORENSICS_DATA_DIR', str(PROJECT_ROOT / 'data'))).resolve()
DATASETS_DIR = PROJECT_ROOT / 'datasets'
REAL_P4_DB = DATA_DIR / 'real_p4.db'
BENCHMARK_DB = DATA_DIR / 'benchmark_p6.db'
