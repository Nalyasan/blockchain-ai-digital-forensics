#!/usr/bin/env python3
"""Backward-compatibility shim for train_ml_model.py."""
import runpy
from pathlib import Path

target = Path(__file__).resolve().parent / "train_ml_model.py"
runpy.run_path(str(target), run_name="__main__")
