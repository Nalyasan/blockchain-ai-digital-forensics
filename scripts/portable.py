"""Standalone Portable Distribution Packaging Utility for Blockchain + AI Forensics (v6.0).

Builds, security-scans, packages, and verifies a self-contained offline Windows x64
portable distribution archive (.zip) containing all 12 standardized functional components,
contracts, canonical SQLite databases, trained ML models, Halo2 ZKML circuit artifacts,
pinned offline wheels, bundled Foundry + Solc binaries, PowerShell automation scripts,
and SHA256SUMS.txt / MANIFEST_SHA256.txt cryptographic manifests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

CANONICAL_DB_HASHES = {
    "data/forensics.db": "3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001",
    "data/real_p4.db": "6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97",
    "data/benchmark_p6.db": "C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507",
}

REQUIRED_FOUNDRY_BINS = [
    "forge.exe",
    "cast.exe",
    "anvil.exe",
]

OPTIONAL_FOUNDRY_BINS = [
    "solc-0.8.24.exe",
]

ALLOWED_PUBLIC_CIRCUIT_KEYS: Set[str] = {
    "circuits/anomaly_detector_v1/vk.key",
    "circuits/anomaly_detector_v1/pk.key",
}

EXCLUDE_DIRS: Set[str] = {
    ".git",
    ".github",
    ".agents",
    ".cursor",
    "%SystemDrive%",
    "osint-attack-surface",
    "scratch",
    "__pycache__",
    ".pytest_cache",
    "tmp_pytest",
    "tmp_pytest_run",
    "tmp_pytest_workerG5",
    "run-output",
    "out",
    "cache",
    "contracts/out",
    "contracts/cache",
    "dist",
    "venv",
    ".venv",
}

EXCLUDE_FILE_PATTERNS: Set[str] = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".db-shm",
    ".db-wal",
    ".key",
    ".pem",
}

EXCLUDE_EXACT_FILES: Set[str] = {
    ".env",
    ".gitignore",
    ".gitattributes",
}

HOST_PATH_REGEX = re.compile(r"(D:[/\\]+Projest|C:[/\\]+Users[/\\]+Naly)", re.IGNORECASE)
SECRET_LEAK_REGEX = re.compile(r"(AIzaSy[0-9A-Za-z_-]{33}|sk-or-v1-[0-9a-f]{48,})")
SCANNABLE_CODE_EXTENSIONS: Set[str] = {".py", ".ps1", ".bat", ".sol", ".toml", ".ini"}


def compute_sha256(file_path: Path) -> str:
    """Compute uppercase SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()


def compute_bytes_sha256(data: bytes) -> str:
    """Compute uppercase SHA-256 hash of in-memory bytes."""
    return hashlib.sha256(data).hexdigest().upper()


def should_exclude(rel_path: str) -> bool:
    """Determine whether a relative file path should be excluded from distribution."""
    norm = rel_path.replace("\\", "/")
    if norm in ALLOWED_PUBLIC_CIRCUIT_KEYS:
        return False

    parts = norm.split("/")
    for i in range(1, len(parts)):
        sub_dir = "/".join(parts[:i])
        dir_name = parts[i - 1]
        if dir_name in EXCLUDE_DIRS or sub_dir in EXCLUDE_DIRS:
            return True

    file_name = parts[-1]
    if file_name in EXCLUDE_EXACT_FILES:
        return True
    if file_name.startswith(".env.") and file_name != ".env.example":
        return True

    for pat in EXCLUDE_FILE_PATTERNS:
        if file_name.lower().endswith(pat.lower()):
            return True

    return False


def verify_canonical_databases(root_dir: Path) -> Dict[str, Tuple[bool, str, str]]:
    """Check integrity of canonical SQLite databases against expected SHA-256 hashes."""
    results = {}
    for rel_path, expected_hash in CANONICAL_DB_HASHES.items():
        full_path = root_dir / rel_path
        if not full_path.exists():
            results[rel_path] = (False, "FILE_NOT_FOUND", expected_hash)
            continue
        actual_hash = compute_sha256(full_path)
        is_match = actual_hash == expected_hash
        results[rel_path] = (is_match, actual_hash, expected_hash)
    return results


def find_wheels_directory(root_dir: Path, candidate_dir: Optional[Path] = None) -> Optional[Path]:
    """Locate the offline wheels repository without hardcoded machine paths."""
    candidates: List[Path] = []
    if candidate_dir:
        candidates.append(candidate_dir)
    env_wheels = os.environ.get("FORENSICS_WHEELS_DIR") if "os" in globals() else None
    if env_wheels:
        candidates.append(Path(env_wheels))
    candidates.extend([
        root_dir / "wheels",
        root_dir.parent / "P3_1B_PYTHON_WHEELS_20261102",
    ])
    for c in candidates:
        if c.exists() and len(list(c.glob("*.whl"))) >= 50:
            return c
    return None


import os


def collect_source_files(root_dir: Path) -> List[Tuple[Path, str]]:
    """Collect all eligible source, model, circuit, documentation, and tool files."""
    collected_map: Dict[str, Path] = {}

    scan_subdirs = [
        "forensics",
        "contracts",
        "scripts",
        "tests",
        "models",
        "circuits",
        "docs",
        "reports",
        "results",
    ]
    for subdir in scan_subdirs:
        sub_path = root_dir / subdir
        if not sub_path.exists():
            continue
        for p in sorted(sub_path.rglob("*")):
            if p.is_file():
                rel = p.relative_to(root_dir).as_posix()
                if not should_exclude(rel):
                    collected_map[rel] = p

    for db_rel in CANONICAL_DB_HASHES:
        db_path = root_dir / db_rel
        if db_path.exists():
            collected_map[Path(db_rel).as_posix()] = db_path

    for tool_name in REQUIRED_FOUNDRY_BINS:
        tool_path = root_dir / "tools" / "foundry" / tool_name
        if tool_path.exists():
            collected_map[f"tools/foundry/{tool_name}"] = tool_path
        else:
            raise FileNotFoundError(f"Missing required Foundry binary: {tool_path}")

    for opt_tool in OPTIONAL_FOUNDRY_BINS:
        opt_path = root_dir / "tools" / "foundry" / opt_tool
        if opt_path.exists():
            collected_map[f"tools/foundry/{opt_tool}"] = opt_path

    root_files = [
        "AGENT.md",
        "PROJECT_HANDOFF.md",
        "README_SETUP.md",
        "PORTABILITY_TEST_REPORT.md",
        "LICENSES_AND_DATA_RIGHTS.md",
        "cleanup_manifest.json",
        "setup.ps1",
        "smoke_test.ps1",
        "run_full_tests.ps1",
        "verify_integrity.ps1",
        "collector.py",
        "mock_rpc.py",
        "pytest.ini",
        ".env.example",
        "run_tests.bat",
        "run_evaluation.bat",
        "setup_env.bat",
        "requirements.txt",
        "requirements.lock.txt",
        "requirements-ml-zkml.lock.txt",
        "README.txt",
        "PROJECT.txt",
        "COMPLETION_REPORT.txt",
        "P1_P6_STATUS_MATRIX.csv",
        "BACKUP_RESTORATION.txt",
    ]
    for rf in root_files:
        p = root_dir / rf
        if p.exists() and not should_exclude(rf):
            collected_map[rf] = p

    return [(src, rel) for rel, src in sorted(collected_map.items(), key=lambda x: x[0])]


def audit_staged_tree(stage_dir: Path) -> None:
    """Fail-closed scan for forbidden credentials, .env files, or hardcoded host paths in code."""
    if (stage_dir / ".env").exists():
        raise ValueError("SECURITY VIOLATION: Live .env file staged for distribution!")

    violations: List[str] = []
    for p in sorted(stage_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(stage_dir).as_posix()
        if p.suffix.lower() in SCANNABLE_CODE_EXTENSIONS:
            txt = p.read_text(encoding="utf-8", errors="ignore")
            # scripts/portable.py legitimately holds HOST_PATH_REGEX to detect host paths
            if rel != "scripts/portable.py":
                for idx, line in enumerate(txt.splitlines(), 1):
                    if HOST_PATH_REGEX.search(line):
                        violations.append(f"Hardcoded host path in {rel}:{idx}: {line.strip()[:100]}")
            for idx, line in enumerate(txt.splitlines(), 1):
                if SECRET_LEAK_REGEX.search(line):
                    violations.append(f"Potential API key leak in {rel}:{idx}")

    if violations:
        joined = "\n  - ".join(violations[:20])
        raise ValueError(f"PORTABILITY / SECURITY STAGING GATE FAILED:\n  - {joined}")


def build_distribution(
    root_dir: Path,
    out_dir: Path,
    archive_name: str = "blockchain_ai_forensics_portable_v6.0.0.zip",
    wheels_dir: Optional[Path] = None,
    include_wheels: bool = True,
    dry_run: bool = False,
) -> Path:
    """Build a standalone portable .zip distribution package compliant with AGENT.md v6.0 §10."""
    root_dir = root_dir.resolve()
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    archive_path = out_dir / archive_name

    print("[*] Packaging standalone portable distribution (AGENT.md v6.0)...")
    print(f"    Source root: {root_dir}")
    print(f"    Output zip:  {archive_path}")

    db_results = verify_canonical_databases(root_dir)
    for db_path, (match, actual, expected) in db_results.items():
        if not match:
            raise ValueError(
                f"Canonical database hash mismatch for {db_path}!\n"
                f"  Actual:   {actual}\n"
                f"  Expected: {expected}"
            )
        print(f"    [OK] Canonical DB verified: {db_path} ({actual[:16]}...)")

    files_to_pack = collect_source_files(root_dir)
    print(f"    [OK] Collected {len(files_to_pack)} project files")

    if include_wheels:
        actual_wheels_dir = find_wheels_directory(root_dir, wheels_dir)
        if not actual_wheels_dir:
            raise FileNotFoundError(
                "Offline wheels directory not found! Pinned wheels are required for standalone offline distribution."
            )
        wheel_files = sorted(actual_wheels_dir.glob("*.whl"))
        print(f"    [OK] Bundling {len(wheel_files)} offline wheels from {actual_wheels_dir}")
        for wf in wheel_files:
            files_to_pack.append((wf, f"wheels/{wf.name}"))
        hashes_csv = actual_wheels_dir / "wheel-hashes.csv"
        if hashes_csv.exists():
            files_to_pack.append((hashes_csv, "wheels/wheel-hashes.csv"))

    if dry_run:
        print("[*] DRY RUN COMPLETE. Files to include:")
        total_sz = sum(p.stat().st_size for p, _ in files_to_pack)
        for _, rel in sorted(files_to_pack, key=lambda x: x[1]):
            print(f"  {rel}")
        print(f"Total files: {len(files_to_pack)}, Total size: {total_sz:,} bytes")
        return archive_path

    with tempfile.TemporaryDirectory(prefix="portable_stage_") as stage_str:
        stage_dir = Path(stage_str)
        manifest_entries: List[Tuple[str, str]] = []

        print("[*] Staging files and running portability/security audit...")
        for src_path, rel_path in files_to_pack:
            dest_path = stage_dir / rel_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dest_path)
            manifest_entries.append((compute_sha256(dest_path), rel_path))

        audit_staged_tree(stage_dir)
        print("    [OK] Staging security & zero-host-path audit passed")

        total_uncompressed = sum(
            (stage_dir / rel).stat().st_size for _, rel in manifest_entries if (stage_dir / rel).exists()
        )
        commit_sha = "UNKNOWN"
        try:
            res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root_dir,
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                commit_sha = res.stdout.strip()
        except Exception:
            pass

        bundled_bins = [
            b for b in (REQUIRED_FOUNDRY_BINS + OPTIONAL_FOUNDRY_BINS)
            if (stage_dir / "tools" / "foundry" / b).exists()
        ]
        info_data = {
            "package_name": archive_name,
            "spec_version": "AGENT.md v6.0",
            "git_commit": commit_sha,
            "build_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "total_files": len(manifest_entries) + 1,
            "total_uncompressed_bytes": total_uncompressed,
            "canonical_databases": CANONICAL_DB_HASHES,
            "bundled_foundry_binaries": bundled_bins,
            "offline_wheels_included": include_wheels,
            "python_target": "CPython 3.13 (win_amd64)",
        }
        info_file = stage_dir / "MANIFEST_INFO.json"
        info_file.write_text(json.dumps(info_data, indent=2), encoding="utf-8")
        manifest_entries.append((compute_sha256(info_file), "MANIFEST_INFO.json"))
        manifest_entries.sort(key=lambda x: x[1])

        manifest_body = "".join(f"{sha}  {rel}\n" for sha, rel in manifest_entries)
        sha256sums_file = stage_dir / "SHA256SUMS.txt"
        manifest_file = stage_dir / "MANIFEST_SHA256.txt"
        sha256sums_file.write_text(manifest_body, encoding="utf-8")
        manifest_file.write_text(manifest_body, encoding="utf-8")
        print(f"    [OK] Generated SHA256SUMS.txt & MANIFEST_SHA256.txt ({len(manifest_entries)} files)")

        shutil.copy2(sha256sums_file, out_dir / "SHA256SUMS.txt")
        shutil.copy2(manifest_file, out_dir / "MANIFEST_SHA256.txt")

        print(f"[*] Compressing into zip archive: {archive_path}...")
        if archive_path.exists():
            archive_path.unlink()

        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            zf.write(sha256sums_file, "SHA256SUMS.txt")
            zf.write(manifest_file, "MANIFEST_SHA256.txt")
            zf.write(info_file, "MANIFEST_INFO.json")
            for _, rel_path in manifest_entries:
                if rel_path in ("SHA256SUMS.txt", "MANIFEST_SHA256.txt", "MANIFEST_INFO.json"):
                    continue
                zf.write(stage_dir / rel_path, rel_path)

    archive_sha = compute_sha256(archive_path)
    archive_size = archive_path.stat().st_size
    sha_file = out_dir / f"{archive_name}.sha256"
    sha_file.write_text(f"{archive_sha} *{archive_name}\n", encoding="utf-8")

    print("[*] DISTRIBUTION PACKAGE CREATED SUCCESSFULLY!")
    print(f"    Path:     {archive_path}")
    print(f"    Size:     {archive_size:,} bytes ({archive_size / (1024*1024):.2f} MB)")
    print(f"    SHA-256:  {archive_sha}")
    print(f"    Checksum: {sha_file}")

    return archive_path


def verify_distribution(archive_path: Path) -> bool:
    """Verify integrity of a distribution zip archive against SHA256SUMS.txt / MANIFEST_SHA256.txt."""
    archive_path = archive_path.resolve()
    if not archive_path.exists():
        print(f"[!] Archive not found: {archive_path}")
        return False

    print(f"[*] Verifying distribution archive: {archive_path}...")
    with zipfile.ZipFile(archive_path, "r") as zf:
        namelist = set(zf.namelist())
        manifest_name = "SHA256SUMS.txt" if "SHA256SUMS.txt" in namelist else (
            "MANIFEST_SHA256.txt" if "MANIFEST_SHA256.txt" in namelist else None
        )
        if not manifest_name:
            print("[!] FAIL: Neither SHA256SUMS.txt nor MANIFEST_SHA256.txt found in archive!")
            return False

        manifest_raw = zf.read(manifest_name).decode("utf-8")
        manifest_lines = [line.strip() for line in manifest_raw.splitlines() if line.strip()]

        total = len(manifest_lines)
        passed = 0
        failed = 0

        for line in manifest_lines:
            parts = line.split("  ", 1)
            if len(parts) != 2:
                parts = line.split(" ", 1)
            expected_sha = parts[0].strip().upper()
            rel_path = parts[1].lstrip("*").strip()

            if rel_path not in namelist:
                print(f"    [!] MISSING: {rel_path}")
                failed += 1
                continue

            actual_sha = compute_bytes_sha256(zf.read(rel_path))
            if actual_sha != expected_sha:
                print(f"    [!] MISMATCH: {rel_path} (got {actual_sha}, expected {expected_sha})")
                failed += 1
            else:
                passed += 1

        print(f"[*] Verification result ({manifest_name}): {passed}/{total} files passed integrity check.")
        if failed == 0:
            print("[*] AUDIT PASS: Distribution archive is 100% verified intact!")
            return True
        print(f"[!] AUDIT FAIL: {failed} files failed verification!")
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", help="Build standalone portable distribution zip")
    build_parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root directory (default: parent of scripts/)",
    )
    build_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "dist",
        help="Output directory for zip archive (default: dist/)",
    )
    build_parser.add_argument(
        "--archive-name",
        type=str,
        default="blockchain_ai_forensics_portable_v6.0.0.zip",
        help="Name of distribution zip archive",
    )
    build_parser.add_argument(
        "--wheels-dir",
        type=Path,
        default=None,
        help="Directory containing pinned offline wheels",
    )
    build_parser.add_argument(
        "--no-wheels",
        action="store_true",
        help="Exclude offline wheels from distribution archive",
    )
    build_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Dry run: print files that would be packaged without creating zip",
    )

    verify_parser = subparsers.add_parser("verify", help="Verify integrity of an existing distribution zip")
    verify_parser.add_argument(
        "archive",
        type=Path,
        help="Path to distribution zip archive",
    )

    args = parser.parse_args(argv)

    if args.command == "build":
        build_distribution(
            root_dir=args.root,
            out_dir=args.output_dir,
            archive_name=args.archive_name,
            wheels_dir=args.wheels_dir,
            include_wheels=not args.no_wheels,
            dry_run=args.dry_run,
        )
        return 0

    if args.command == "verify":
        ok = verify_distribution(args.archive)
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
