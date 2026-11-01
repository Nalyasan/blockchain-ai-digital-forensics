"""Opt-in integration isolation; never run mutation probes on original evidence."""
import hashlib
import os
from pathlib import Path
import shutil

import pytest


def pytest_collection_modifyitems(items):
    if os.environ.get("INTEGRATION_NO_ACL_CHANGES") == "1":
        for item in items:
            if item.path.name == "test_onchain_group1b.py":
                item.add_marker(pytest.mark.skip(reason="User forbids NTFS ACL changes; P3-1b calls icacls"))


@pytest.fixture(scope="session", autouse=True)
def isolated_integration_evidence(request, tmp_path_factory):
    source = os.environ.get("INTEGRATION_EVIDENCE_DB")
    if not source:
        yield
        return
    original = Path(source)
    expected = "6bd9aed48ac2742d0862198bff65994861244ec681dc8abeb3e6f771e7808c97"
    assert hashlib.sha256(original.read_bytes()).hexdigest() == expected
    copied = tmp_path_factory.mktemp("canonical-copy") / "real_p4.db"
    shutil.copyfile(original, copied)
    assert hashlib.sha256(copied.read_bytes()).hexdigest() == expected
    patch = pytest.MonkeyPatch()
    for module in {item.module for item in request.session.items}:
        for name in ("REAL_P4_DB", "REAL_P4_DB_PATH", "DB_PATH", "DEFAULT_DB_PATH"):
            value = getattr(module, name, None)
            if isinstance(value, Path) and value.name == "real_p4.db":
                patch.setattr(module, name, copied)
        if hasattr(module, "REAL_P4_DATA_DIR"):
            patch.setattr(module, "REAL_P4_DATA_DIR", copied.parent)
    yield
    patch.undo()
    assert hashlib.sha256(original.read_bytes()).hexdigest() == expected
