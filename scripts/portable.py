"""Standalone Portable Distribution Packaging Utility for Blockchain + AI Forensics (Phase G6A).

Builds, packages, and verifies a self-contained portable distribution archive (.zip)
containing source code, contracts, canonical SQLite databases, pinned offline wheels,
bundled Foundry binaries, and execution entry points with a SHA-256 checksum manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

# Canonical database checksum invariants verified in Gate G5
CANONICAL_DB_HASHES = {
    "data/forensics.db": "3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001",
    "data/real_p4.db": "6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97",
    "data/benchmark_p6.db": "C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507",
}

# Foundry binaries required for smart contract operations
REQUIRED_FOUNDRY_BINS = [
    "forge.exe",
    "cast.exe",
    "anvil.exe",
]

# Patterns and folders to strictly exclude from release distribution
EXCLUDE_DIRS: Set[str] = {
    ".git",
    ".github",
    ".agents",
    ".cursor",
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
    ".env",  # Exclude live credentials; bundle .env.example
}

EXCLUDE_EXACT_FILES: Set[str] = {
    ".gitignore",
    ".gitattributes",
}


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
    parts = rel_path.replace("\\", "/").split("/")
    
    # Check directory exclusions
    for i in range(1, len(parts)):
        sub_dir = "/".join(parts[:i])
        dir_name = parts[i - 1]
        if dir_name in EXCLUDE_DIRS or sub_dir in EXCLUDE_DIRS:
            return True
            
    file_name = parts[-1]
    if file_name in EXCLUDE_EXACT_FILES:
        return True
        
    for pat in EXCLUDE_FILE_PATTERNS:
        if file_name.endswith(pat):
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
        is_match = (actual_hash == expected_hash)
        results[rel_path] = (is_match, actual_hash, expected_hash)
    return results


def find_wheels_directory(root_dir: Path, candidate_dir: Optional[Path] = None) -> Optional[Path]:
    """Locate the offline wheels repository containing 101 pinned wheels."""
    candidates = []
    if candidate_dir:
        candidates.append(candidate_dir)
    candidates.extend([
        root_dir.parent / "P3_1B_PYTHON_WHEELS_20261102",
        root_dir / "wheels",
        Path("D:/Projest/P3_1B_PYTHON_WHEELS_20261102"),
    ])
    for c in candidates:
        if c.exists() and len(list(c.glob("*.whl"))) >= 50:
            return c
    return None


def collect_source_files(root_dir: Path) -> List[Tuple[Path, str]]:
    """Collect all eligible source files relative to root_dir."""
    collected: List[Tuple[Path, str]] = []
    
    # 1. Subdirectories to scan
    scan_subdirs = ["forensics", "contracts", "scripts", "tests"]
    for subdir in scan_subdirs:
        sub_path = root_dir / subdir
        if not sub_path.exists():
            continue
        for p in sub_path.rglob("*"):
            if p.is_file():
                rel = p.relative_to(root_dir).as_posix()
                if not should_exclude(rel):
                    collected.append((p, rel))
                    
    # 2. Canonical data files (explicit inclusion)
    for db_rel in CANONICAL_DB_HASHES.keys():
        db_path = root_dir / db_rel
        if db_path.exists():
            collected.append((db_path, Path(db_rel).as_posix()))

    # 3. Bundled Foundry tools
    for tool_name in REQUIRED_FOUNDRY_BINS:
        tool_path = root_dir / "tools" / "foundry" / tool_name
        if tool_path.exists():
            collected.append((tool_path, f"tools/foundry/{tool_name}"))
        else:
            raise FileNotFoundError(f"Missing required Foundry binary: {tool_path}")

    # 4. Root configuration and entrypoint files
    root_files = [
        "collector.py",
        "pytest.ini",
        ".env.example",
        "run_tests.bat",
        "run_evaluation.bat",
        "setup_env.bat",
        "requirements.txt",
        "README.txt",
    ]
    for rf in root_files:
        p = root_dir / rf
        if p.exists():
            collected.append((p, rf))

    return collected


def build_distribution(
    root_dir: Path,
    out_dir: Path,
    archive_name: str = "blockchain_ai_forensics_portable_v1.0.0.zip",
    wheels_dir: Optional[Path] = None,
    include_wheels: bool = True,
    dry_run: bool = False,
) -> Path:
    """Build a standalone portable .zip distribution package."""
    root_dir = root_dir.resolve()
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    archive_path = out_dir / archive_name

    print(f"[*] Packaging standalone portable distribution...")
    print(f"    Source root: {root_dir}")
    print(f"    Output zip:  {archive_path}")

    # 1. Validate Canonical Databases
    db_results = verify_canonical_databases(root_dir)
    for db_path, (match, actual, expected) in db_results.items():
        if not match:
            raise ValueError(
                f"Canonical database hash mismatch for {db_path}!\n"
                f"  Actual:   {actual}\n"
                f"  Expected: {expected}"
            )
        print(f"    [OK] Canonical DB verified: {db_path} ({actual[:16]}...)")

    # 2. Collect Source Files
    files_to_pack = collect_source_files(root_dir)
    print(f"    [OK] Collected {len(files_to_pack)} project files")

    # 3. Locate Wheels
    if include_wheels:
        actual_wheels_dir = find_wheels_directory(root_dir, wheels_dir)
        if not actual_wheels_dir:
            raise FileNotFoundError(
                "Offline wheels directory not found! Pinned wheels are required for standalone offline distribution."
            )
        wheel_files = list(actual_wheels_dir.glob("*.whl"))
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

    # 4. Create Temporary Staging Directory to Generate Manifest
    with tempfile.TemporaryDirectory(prefix="portable_stage_") as stage_str:
        stage_dir = Path(stage_str)
        manifest_entries: List[Tuple[str, str]] = []

        print(f"[*] Staging files and computing SHA-256 manifest...")
        for src_path, rel_path in files_to_pack:
            dest_path = stage_dir / rel_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dest_path)
            
            file_sha = compute_sha256(dest_path)
            manifest_entries.append((file_sha, rel_path))

        # Sort manifest entries alphabetically by relative path
        manifest_entries.sort(key=lambda x: x[1])

        # Write MANIFEST_SHA256.txt
        manifest_file = stage_dir / "MANIFEST_SHA256.txt"
        with open(manifest_file, "w", encoding="utf-8") as f:
            for sha, rel in manifest_entries:
                f.write(f"{sha}  {rel}\n")
        print(f"    [OK] Generated MANIFEST_SHA256.txt ({len(manifest_entries)} files)")

        # Write MANIFEST_INFO.json with packaging metadata
        total_uncompressed = sum(dest_path.stat().st_size for _, rel in manifest_entries if (stage_dir / rel).exists())
        info_data = {
            "package_name": archive_name,
            "build_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "total_files": len(manifest_entries),
            "total_uncompressed_bytes": total_uncompressed,
            "canonical_databases": CANONICAL_DB_HASHES,
            "bundled_foundry_binaries": REQUIRED_FOUNDRY_BINS,
            "offline_wheels_included": include_wheels,
            "python_target": "CPython 3.13 (win_amd64)",
        }
        info_file = stage_dir / "MANIFEST_INFO.json"
        info_file.write_text(json.dumps(info_data, indent=2), encoding="utf-8")
        manifest_entries.append((compute_sha256(info_file), "MANIFEST_INFO.json"))

        # 5. Compress to Zip Archive
        print(f"[*] Compressing into zip archive: {archive_path}...")
        if archive_path.exists():
            archive_path.unlink()

        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            # Add manifest and info first
            zf.write(manifest_file, "MANIFEST_SHA256.txt")
            zf.write(info_file, "MANIFEST_INFO.json")
            for _, rel_path in manifest_entries:
                if rel_path in ("MANIFEST_SHA256.txt", "MANIFEST_INFO.json"):
                    continue
                file_on_disk = stage_dir / rel_path
                zf.write(file_on_disk, rel_path)

    # 6. Compute Checksum of Distribution Archive
    archive_sha = compute_sha256(archive_path)
    archive_size = archive_path.stat().st_size
    sha_file = out_dir / f"{archive_name}.sha256"
    sha_file.write_text(f"{archive_sha} *{archive_name}\n", encoding="utf-8")

    print(f"[*] DISTRIBUTION PACKAGE CREATED SUCCESSFULLY!")
    print(f"    Path:     {archive_path}")
    print(f"    Size:     {archive_size:,} bytes ({archive_size / (1024*1024):.2f} MB)")
    print(f"    SHA-256:  {archive_sha}")
    print(f"    Checksum: {sha_file}")

    return archive_path


def verify_distribution(archive_path: Path) -> bool:
    """Verify integrity of a distribution zip archive against its bundled MANIFEST_SHA256.txt."""
    archive_path = archive_path.resolve()
    if not archive_path.exists():
        print(f"[!] Archive not found: {archive_path}")
        return False

    print(f"[*] Verifying distribution archive: {archive_path}...")
    with zipfile.ZipFile(archive_path, "r") as zf:
        namelist = set(zf.namelist())
        if "MANIFEST_SHA256.txt" not in namelist:
            print("[!] FAIL: MANIFEST_SHA256.txt missing in archive!")
            return False

        # Read manifest
        manifest_raw = zf.read("MANIFEST_SHA256.txt").decode("utf-8")
        manifest_lines = [line.strip() for line in manifest_raw.splitlines() if line.strip()]

        total = len(manifest_lines)
        passed = 0
        failed = 0

        for line in manifest_lines:
            parts = line.split("  ", 1)
            if len(parts) != 2:
                parts = line.split(" ", 1)
            expected_sha = parts[0].strip().upper()
            rel_path = parts[1].strip()

            if rel_path not in namelist:
                print(f"    [!] MISSING: {rel_path}")
                failed += 1
                continue

            content = zf.read(rel_path)
            actual_sha = compute_bytes_sha256(content)
            if actual_sha != expected_sha:
                print(f"    [!] MISMATCH: {rel_path} (got {actual_sha}, expected {expected_sha})")
                failed += 1
            else:
                passed += 1

        print(f"[*] Verification result: {passed}/{total} files passed integrity check.")
        if failed == 0:
            print("[*] AUDIT PASS: Distribution archive is 100% verified intact!")
            return True
        else:
            print(f"[!] AUDIT FAIL: {failed} files failed verification!")
            return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: build
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
        default="blockchain_ai_forensics_portable_v1.0.0.zip",
        help="Name of distribution zip archive",
    )
    build_parser.add_argument(
        "--wheels-dir",
        type=Path,
        default=None,
        help="Directory containing 101 pinned offline wheels",
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

    # Subcommand: verify
    verify_parser = subparsers.add_parser("verify", help="Verify integrity of an existing distribution zip")
    verify_parser.add_argument(
        "archive",
        type=Path,
        help="Path to distribution zip archive",
    )

    args = parser.parse_args(argv)

    if args.command == "build":
        pkg = build_distribution(
            root_dir=args.root,
            out_dir=args.output_dir,
            archive_name=args.archive_name,
            wheels_dir=args.wheels_dir,
            include_wheels=not args.no_wheels,
            dry_run=args.dry_run,
        )
        return 0

    elif args.command == "verify":
        ok = verify_distribution(args.archive)
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
