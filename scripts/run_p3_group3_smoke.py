#!/usr/bin/env python3
"""Backward-compatibility shim for run_onchain_journal_smoke.py."""
import runpy
from pathlib import Path

target = Path(__file__).resolve().parent / "run_onchain_journal_smoke.py"
runpy.run_path(str(target), run_name="__main__")
