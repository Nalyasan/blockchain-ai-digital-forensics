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
import forensics.onchain as onchain
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

def cli_anchor(args):
    """Neo gói chứng cứ lên blockchain qua EvidenceRegistry."""
    try:
        res = onchain.anchor_evidence(
            manifest_path_or_dir=args.manifest_path,
            contract_address=args.contract,
            db_path=args.db,
            account=args.account,
            password_file=args.password_file,
            from_addr=args.from_addr,
            allow_dirty=args.allow_dirty,
            rpc_url=args.rpc_url
        )
        print("OK: Neo chứng cứ thành công lên blockchain!")
        print(f"  Evidence ID: {res['evidence_id']}")
        print(f"  Tx Hash: {res['tx_hash']}")
        print(f"  Block: {res['block_number']}")
        print(f"  Contract: {res['contract_address']}")
        print(f"  Manifest SHA-256: {res['manifest_sha256']}")
        return 0
    except Exception as e:
        print(f"THẤT BẠI anchor: {e}", file=sys.stderr)
        return 1

def cli_custody(args):
    """Ghi nhận hành trình chứng cứ (CustodyRecord) on-chain."""
    try:
        res = onchain.record_custody_action(
            evidence_id=args.evidence_id,
            action=args.action,
            artifact_sha256=args.artifact_hash,
            note=args.note,
            contract_address=args.contract,
            db_path=args.db,
            account=args.account,
            password_file=args.password_file,
            from_addr=args.from_addr,
            rpc_url=args.rpc_url
        )
        print("OK: Ghi nhận custody event thành công!")
        print(f"  Evidence ID: {res['evidence_id']}")
        print(f"  Action: {res['action']}")
        print(f"  Tx Hash: {res['tx_hash']}")
        print(f"  Block: {res['block_number']}")
        return 0
    except Exception as e:
        print(f"THẤT BẠI custody: {e}", file=sys.stderr)
        return 1

def cli_verify_onchain(args):
    """Xác minh tầng 3: đối chiếu manifest trên đĩa với bản ghi on-chain."""
    ok, msg = onchain.verify_onchain_evidence(
        manifest_path_or_dir=args.manifest_path,
        contract_address=args.contract,
        evidence_id=args.evidence_id,
        db_path=args.db,
        rpc_url=args.rpc_url
    )
    if ok:
        print(f"OK: {msg}")
        return 0
    else:
        print(f"THẤT BẠI: {msg}", file=sys.stderr)
        return 1

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

    # 6. anchor
    pa = sub.add_parser("anchor", help="Neo gói chứng cứ lên smart contract EvidenceRegistry")
    pa.add_argument("manifest_path", help="Đường dẫn đến manifest.json hoặc thư mục gói chứng cứ")
    pa.add_argument("--contract", required=True, help="Địa chỉ hợp đồng EvidenceRegistry")
    pa.add_argument("--db", default=None, help="Đường dẫn database SQLite")
    pa.add_argument("--account", default=None, help="Tên tài khoản keystore của Foundry cast")
    pa.add_argument("--password-file", default=None, help="Tệp chứa mật khẩu giải mã keystore")
    pa.add_argument("--from", dest="from_addr", default=None, help="Địa chỉ ví người ký (dùng cho Anvil / unlocked)")
    pa.add_argument("--allow-dirty", action="store_true", help="Cho phép neo kể cả khi working_tree_dirty=True")
    pa.add_argument("--rpc-url", default=None, help="RPC URL của mạng blockchain")
    pa.set_defaults(func=cli_anchor)

    # 7. custody
    pc = sub.add_parser("custody", help="Ghi nhận sự kiện hành trình chứng cứ (CustodyRecord) on-chain")
    pc.add_argument("--evidence-id", type=int, required=True, help="ID của chứng cứ trên hợp đồng")
    pc.add_argument("--action", type=int, required=True, choices=[0, 1, 2, 3], help="Hành động: 0=COLLECTED, 1=ANALYZED, 2=TRANSFERRED, 3=EXPORTED")
    pc.add_argument("--artifact-hash", required=True, help="SHA-256 của file bằng chứng / báo cáo")
    pc.add_argument("--note", required=True, help="Ghi chú hành trình")
    pc.add_argument("--contract", required=True, help="Địa chỉ hợp đồng EvidenceRegistry")
    pc.add_argument("--db", default=None, help="Đường dẫn database SQLite")
    pc.add_argument("--account", default=None, help="Tên tài khoản keystore của Foundry cast")
    pc.add_argument("--password-file", default=None, help="Tệp mật khẩu giải mã keystore")
    pc.add_argument("--from", dest="from_addr", default=None, help="Địa chỉ ví người ký")
    pc.add_argument("--rpc-url", default=None, help="RPC URL")
    pc.set_defaults(func=cli_custody)

    # 8. verify-onchain
    pvo = sub.add_parser("verify-onchain", help="Xác minh tầng 3: đối chiếu manifest với hợp đồng on-chain")
    pvo.add_argument("manifest_path", help="Đường dẫn đến manifest.json hoặc thư mục gói chứng cứ")
    pvo.add_argument("--contract", required=True, help="Địa chỉ hợp đồng EvidenceRegistry")
    pvo.add_argument("--evidence-id", type=int, default=None, help="ID chứng cứ (nếu không tra cứu từ DB)")
    pvo.add_argument("--db", default=None, help="Đường dẫn database SQLite")
    pvo.add_argument("--rpc-url", default=None, help="RPC URL")
    pvo.set_defaults(func=cli_verify_onchain)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
