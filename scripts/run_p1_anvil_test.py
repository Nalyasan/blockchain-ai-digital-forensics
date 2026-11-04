#!/usr/bin/env python3
"""Backward-compatibility shim for run_collector_anvil_test.py."""
import runpy
from pathlib import Path

target = Path(__file__).resolve().parent / "run_collector_anvil_test.py"
runpy.run_path(str(target), run_name="__main__")
