"""Giao diện dòng lệnh CLI cho hệ thống Forensics (Mục 6.2, 6.3 & P2).
Hỗ trợ:
- export-evidence
- verify-local
- verify-manifest
- verify-rpc
- verify-derived
"""
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import os
import argparse
import logging
from forensics.evidence import export_evidence, verify_manifest, validate_case_id
from forensics.schemas import init_db
import collector

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("forensics.cli")

def cli_export_evidence(args):
    """Lệnh xuất gói chứng cứ tái lập."""
    try:
        manifest = export_evidence(
            case_id=args.case_id,
            start_block=args.start_block,
            end_block=args.end_block,
            out_dir=args.out_dir,
            db_path=args.db,
            operator=args.operator,
            allow_gaps=args.allow_gaps,
            require_final=args.require_final
        )
        print(f"OK: Đã xuất thành công gói chứng cứ '{args.case_id}'")
        print(f"  Thư mục: {args.out_dir or os.path.join('evidence', args.case_id)}")
        print(f"  Package Digest: {manifest['package_digest']}")
        print(f"  Blocks: {manifest['counts']['total_blocks']} | Txs: {manifest['counts']['transactions']} | Transfers: {manifest['counts']['asset_transfers']}")
        return 0
    except Exception as e:
        print(f"LỖI export-evidence: {e}", file=sys.stderr)
        return 1

def cli_verify_manifest(args):
    """Lệnh xác minh toàn vẹn gói chứng cứ và manifest.json trên đĩa."""
    valid, errors = verify_manifest(args.manifest_path, db_path=args.db)
    if valid:
        print(f"OK: Gói chứng cứ '{args.manifest_path}' toàn vẹn và khớp hoàn toàn với manifest.json.")
        return 0
    else:
        print(f"THẤT BẠI: Phát hiện {len(errors)} lỗi toàn vẹn trong gói chứng cứ:")
        for err in errors:
            print(f"  - {err}")
        return 1

def cli_verify_local(args):
    """Kiểm tra toàn vẹn SQLite cục bộ (SHA-256 raw + parentHash + gaps)."""
    db_file = args.db or os.environ.get("DB_PATH", "data/forensics.db")
    if not os.path.exists(db_file):
        print(f"LỖI: Database không tồn tại: {db_file}", file=sys.stderr)
        return 1

    # Sử dụng hàm verify từ collector
    class DummyArgs:
        pass
    collector.DB_PATH = db_file
    return collector.cmd_verify(DummyArgs())

def cli_verify_rpc(args):
    """Bọc lại lệnh verify-rpc từ collector."""
    db_file = args.db or os.environ.get("DB_PATH", "data/forensics.db")
    collector.DB_PATH = db_file
    return collector.cmd_verify_rpc(args)

def cli_verify_derived(args):
    """Bọc lại lệnh verify-derived từ collector."""
    db_file = args.db or os.environ.get("DB_PATH", "data/forensics.db")
    collector.DB_PATH = db_file
    return collector.cmd_verify_derived(args)

def build_parser():
    p = argparse.ArgumentParser(
        prog="python -m forensics.cli",
        description="Bộ công cụ điều tra pháp y Blockchain (Forensics CLI)"
    )
    sub = p.add_subparsers(dest="command", required=True)

    # 1. export-evidence
    pe = sub.add_parser("export-evidence", help="Xuất gói chứng cứ tái lập kèm manifest.json")
    pe.add_argument("--case-id", required=True, help="Mã vụ việc điều tra (chỉ nhận [A-Za-z0-9_-])")
    pe.add_argument("--start-block", type=int, required=True, help="Block bắt đầu")
    pe.add_argument("--end-block", type=int, required=True, help="Block kết thúc")
    pe.add_argument("--out-dir", default=None, help="Thư mục xuất gói chứng cứ (mặc định evidence/<case_id>)")
    pe.add_argument("--db", default=None, help="Đường dẫn file database SQLite")
    pe.add_argument("--operator", default=None, help="Định danh điều tra viên")
    pe.add_argument("--allow-gaps", action="store_true", help="Cho phép xuất kể cả khi thiếu block")
    pe.add_argument("--require-final", action="store_true", help="Từ chối xuất nếu có block chưa finalized")
    pe.set_defaults(func=cli_export_evidence)

    # 2. verify-manifest
    pm = sub.add_parser("verify-manifest", help="Xác minh tính toàn vẹn của gói chứng cứ theo manifest.json")
    pm.add_argument("manifest_path", help="Đường dẫn đến file manifest.json hoặc thư mục gói chứng cứ")
    pm.add_argument("--db", default=None, help="Đường dẫn database SQLite để đối chiếu manifest_sha256")
    pm.set_defaults(func=cli_verify_manifest)

    # 3. verify-local
    pl = sub.add_parser("verify-local", help="Kiểm tra SHA-256 dữ liệu thô và parentHash trong SQLite")
    pl.add_argument("--db", default=None, help="Đường dẫn database SQLite")
    pl.set_defaults(func=cli_verify_local)

    # 4. verify-rpc
    pr = sub.add_parser("verify-rpc", help="Đối chiếu nội dung đầy đủ giữa SQLite và node RPC")
    pr.add_argument("--start-block", type=int, default=None, help="Block bắt đầu")
    pr.add_argument("--end-block", type=int, default=None, help="Block kết thúc")
    pr.add_argument("--db", default=None, help="Đường dẫn database SQLite")
    pr.set_defaults(func=cli_verify_rpc)

    # 5. verify-derived
    pd = sub.add_parser("verify-derived", help="Tính lại asset_transfers từ dữ liệu thô và so sánh")
    pd.add_argument("--db", default=None, help="Đường dẫn database SQLite")
    pd.set_defaults(func=cli_verify_derived)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
