import datetime
import hashlib
import json
from pathlib import Path

worktree_root = Path("D:/Projest/worktrees/p4_real_integration")
main_root = Path("D:/Projest/Blockchain")

with open(worktree_root / "results/p4/protected-before.json", "r", encoding="utf-8-sig") as f:
    before = json.load(f)

after_files = []
for entry in before["files"]:
    p = main_root / entry["path"]
    data = p.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    sz = len(data)
    match = (sha == entry["sha256"]) and (sz == entry["size"])
    after_files.append({
        "path": entry["path"],
        "expected_sha256": entry["sha256"],
        "actual_sha256": sha,
        "sha256": sha,
        "expected_size": entry["size"],
        "actual_size": sz,
        "size": sz,
        "match": match
    })

all_matched = all(f["match"] for f in after_files)
after_data = {
    "audit_title": "P4 Post-Execution Protected Evidence Integrity Audit",
    "audit_timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "baseline_commit": before.get("baseline", "9bed49a7e83a37790013c3e328ae0a41e091bfa1"),
    "total_files": len(after_files),
    "matched_files": sum(1 for f in after_files if f["match"]),
    "mismatched_files": sum(1 for f in after_files if not f["match"]),
    "status": "PASS" if all_matched else "FAIL",
    "files": after_files
}

out_path = worktree_root / "results/p4/protected-after.json"
out_path.write_text(json.dumps(after_data, indent=4), encoding="utf-8")
print(f"Status: {after_data['status']} ({after_data['matched_files']}/{after_data['total_files']})")
