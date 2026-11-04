"""Giao diện dòng lệnh CLI cho hệ thống Digital Forensics (Evidence Package, On-Chain Registry, Rule Engine, AI Investigator).
Hỗ trợ:
- export-evidence
- verify-local
- verify-manifest
- verify-rpc
- verify-derived
- analyze
- investigate
"""
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import os
import json
import argparse
import logging
from forensics.evidence import export_evidence, verify_manifest, validate_case_id
import forensics.onchain as onchain
from forensics.evidence_identity import sanitize_log_text

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("forensics.cli")

def _safe_sanitize(text: str, forbidden: list[str] | None = None) -> str:
    return sanitize_log_text(str(text), forbidden or [])

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
            require_final=args.require_final,
            chain_id=args.chain_id
        )
        print(f"OK: Đã xuất thành công gói chứng cứ '{args.case_id}'")
        print(f"  Thư mục: {args.out_dir or os.path.join('evidence', args.case_id)}")
        print(f"  Package Digest: {manifest['package_digest']}")
        print(f"  Blocks: {manifest['counts']['total_blocks']} | Txs: {manifest['counts']['transactions']} | Transfers: {manifest['counts']['asset_transfers']}")
        return 0
    except Exception as e:
        from forensics.integrity import InvalidPackage
        from forensics.exporter import ExportPolicyError
        # Only application-owned codes/messages may cross this error boundary.
        if isinstance(e, InvalidPackage):
            message = e.code.value
        elif isinstance(e, ExportPolicyError):
            message = str(e)
        elif isinstance(e, FileExistsError):
            message = 'DESTINATION_EXISTS'
        else:
            known = {'GIT_UNKNOWN', 'DATABASE_UNAVAILABLE', 'INVALID_CASE_ID',
                     'EXPORT_INVALID_OR_INCOMPLETE_DATA', 'NO_CLOBBER_UNSUPPORTED', 'PUBLISH_FAILED',
                     'EXPORT_IO_OR_DB_ERROR: published package, if present, is retained'}
            message = str(e) if str(e) in known else 'EXPORT_FAILED'
        print(f"LỖI export-evidence: {message}", file=sys.stderr)
        return 1

def cli_verify_manifest(args):
    """Lệnh xác minh toàn vẹn gói chứng cứ và manifest.json trên đĩa."""
    from forensics.integrity import verify_package
    result = verify_package(args.manifest_path, db_path=args.db)
    print(f"{result.status}: {result.reason_code.value}; coverage={result.coverage}")
    if result.status == 'VALID':
        print('Các file được kiểm tra toàn vẹn và khớp hoàn toàn với manifest.json.')
    return {'VALID': 0, 'INVALID': 1, 'ERROR': 2}[result.status]

def cli_verify_local(args):
    """Kiểm tra toàn vẹn SQLite cục bộ (SHA-256 raw + parentHash + gaps)."""
    import collector
    db_file = args.db or os.environ.get("DB_PATH", "data/forensics.db")
    if not os.path.exists(db_file):
        print(_safe_sanitize(f"LỖI: Database không tồn tại: {db_file}"), file=sys.stderr)
        return 1

    # Sử dụng hàm verify từ collector
    class DummyArgs:
        pass
    collector.DB_PATH = db_file
    return collector.cmd_verify(DummyArgs())

def cli_verify_rpc(args):
    """Bọc lại lệnh verify-rpc từ collector."""
    import collector
    db_file = args.db or os.environ.get("DB_PATH", "data/forensics.db")
    collector.DB_PATH = db_file
    return collector.cmd_verify_rpc(args)

def cli_verify_derived(args):
    """Bọc lại lệnh verify-derived từ collector."""
    import collector
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
            allow_unfinalized=args.allow_unfinalized,
            allow_gaps=args.allow_gaps,
            allow_integrity_failed=args.allow_integrity_failed,
            allow_commit_mismatch=args.allow_commit_mismatch,
            reason=args.reason,
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
        code = 'SIGNER_MISMATCH' if str(e).startswith('SIGNER_MISMATCH:') else 'ANCHOR_FAILED'
        print(_safe_sanitize(f"THẤT BẠI anchor: {code}; kiểm tra audit trước khi thử lại"), file=sys.stderr)
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
        code = 'SIGNER_MISMATCH' if str(e).startswith('SIGNER_MISMATCH:') else 'CUSTODY_FAILED'
        print(_safe_sanitize(f"THẤT BẠI custody: {code}; kết quả gửi có thể chưa xác định"), file=sys.stderr)
        return 1

def cli_verify_onchain(args):
    """Xác minh tầng 3: đối chiếu manifest trên đĩa với bản ghi on-chain."""
    result = onchain.verify_onchain_evidence(
        manifest_path_or_dir=args.manifest_path,
        contract_address=args.contract,
        evidence_id=args.evidence_id,
        db_path=args.db,
        rpc_url=args.rpc_url,
        anchor_chain_id=args.anchor_chain_id,
        legacy_case_encoding=getattr(args, "legacy_case_encoding", False)
    )
    msg = f"{result.status}: {result.reason_code}"
    print(_safe_sanitize(msg), file=sys.stdout if result.exit_code == 0 else sys.stderr)
    return result.exit_code

def cli_reconcile(args):
    """Đối soát trạng thái operation on-chain ở chế độ read-only."""
    from forensics import onchain_store as ops
    db_file = args.db or os.environ.get("DB_PATH", "data/forensics.db")
    rpc_url = args.rpc_url or os.environ.get("ANCHOR_RPC_URL", "http://127.0.0.1:8545")
    try:
        res = ops.reconcile_operation(
            db_path=db_file,
            operation_id=args.operation_id,
            rpc_url_or_client=rpc_url,
            tx_hash=args.tx_hash
        )
        print(_safe_sanitize(json.dumps(res, sort_keys=True, indent=2)))
        return 0 if res.get("reconciled") else 1
    except Exception as e:
        print(_safe_sanitize(f"LỖI reconcile: {e}"), file=sys.stderr)
        return 1

def cli_migrate_db(args):
    """Lệnh migration chủ động cho SQLite lên Group 3 schema."""
    db_file = args.db or os.environ.get("DB_PATH", "data/forensics.db")
    if not os.path.exists(db_file):
        print(f"LỖI: Database không tồn tại: {db_file}", file=sys.stderr)
        return 1
    import sqlite3
    from forensics.schemas import migrate_group3, group3_schema_present
    try:
        conn = sqlite3.connect(db_file)
        migrate_group3(conn)
        conn.close()
        print(f"OK: Đã migrate thành công database '{db_file}' lên Group 3 schema.")
        return 0
    except Exception as e:
        print(f"LỖI migrate-db: {e}", file=sys.stderr)
        return 1

def cli_analyze(args):
    """Lệnh phân tích phát hiện bất thường bằng Rule Engine."""
    if getattr(args, "anchored_manifest", None) or getattr(args, "p3_manifest", None):
        from forensics.rules.anchored import cli_analyze_p3
        return cli_analyze_p3(args)
    from forensics.rules.engine import RuleEngine
    db_file = args.db or os.environ.get("DB_PATH", "data/forensics.db")
    if not os.path.exists(db_file):
        print(_safe_sanitize(f"LỖI analyze: Database không tồn tại: {db_file}"), file=sys.stderr)
        return 1

    token_thresholds = None
    if getattr(args, "token_thresholds", None):
        tt_val = args.token_thresholds
        if os.path.exists(tt_val):
            with open(tt_val, "r", encoding="utf-8") as f:
                token_thresholds = json.load(f)
        else:
            try:
                token_thresholds = json.loads(tt_val)
            except Exception as e:
                print(_safe_sanitize(f"LỖI analyze: Không parse được token-thresholds JSON: {e}"), file=sys.stderr)
                return 1

    try:
        with RuleEngine(
            db_path_or_conn=db_file,
            chain_id=args.chain_id,
            token_thresholds=token_thresholds,
        ) as engine:
            alerts = engine.run(
                test_start_block=args.start_block,
                test_end_block=args.end_block,
                cal_start_block=args.cal_start_block,
                cal_end_block=args.cal_end_block,
                rules=args.rules,
                persist=args.persist,
            )

            # Export if requested
            if args.out:
                fmt = args.format
                if not fmt:
                    fmt = "csv" if str(args.out).lower().endswith(".csv") else "json"
                if fmt == "csv":
                    engine.export_csv(alerts, args.out)
                else:
                    engine.export_json(alerts, args.out)

            print(f"OK: Hoàn tất phân tích Rule Engine trên chain {args.chain_id}.")
            print(f"  Số alerts phát hiện: {len(alerts)}")
            for idx, a in enumerate(alerts[:5], 1):
                reason_snippet = str(a.reason)[:80]
                print(f"  [{idx}] Rule: {a.rule_id} | Asset: {a.asset_id} | Unit: {a.unit_type} | Reason: {reason_snippet}...")
            if len(alerts) > 5:
                print(f"  ... và {len(alerts) - 5} alerts khác.")
            return 0
    except Exception as e:
        print(_safe_sanitize(f"LỖI analyze: {e}"), file=sys.stderr)
        return 1

def cli_investigate(args):
    """Lệnh điều tra pháp y tự động bằng AI Investigator (Pydantic AI + Gemini Flash)."""
    from forensics.ai.db_readonly import readonly_connection
    from forensics.ai.investigator import ForensicInvestigator
    from forensics.ai.provider import get_ai_config

    db_file = args.db or os.environ.get("DB_PATH", "data/forensics.db")
    if not os.path.exists(db_file):
        print(_safe_sanitize(f"LỖI investigate: Database không tồn tại: {db_file}"), file=sys.stderr)
        return 1

    try:
        cfg_kwargs = {}
        if getattr(args, "provider", None):
            cfg_kwargs["provider"] = args.provider
        if getattr(args, "model", None):
            cfg_kwargs["model_name"] = args.model
        if getattr(args, "max_steps", None):
            cfg_kwargs["max_tool_steps"] = args.max_steps
        cfg = get_ai_config(**cfg_kwargs)

        with readonly_connection(db_file) as ro_db:
            inv = ForensicInvestigator(
                config=cfg,
                readonly_db=ro_db,
                strict_ref_checker=getattr(args, "strict_ref_check", False),
            )
            res = inv.investigate(
                case_id=args.case_id,
                query=args.query or f"Investigate case {args.case_id}",
                input_refs=args.refs or [f"case:{args.case_id}"],
            )
            payload = {
                "analysis_id": res.analysis_id,
                "case_id": res.output.case_id,
                "ref_check_status": res.ref_check_status,
                "checked_facts_count": res.checked_facts_count,
                "referenced_canonical_tx_count": res.referenced_canonical_tx_count,
                "existence_ref_ratio": res.existence_ref_ratio,
                "content_match_ratio": res.content_match_ratio,
                "has_content_mismatch": res.has_content_mismatch,
                "injection_detected": res.injection_detected,
                "mismatches": [m.to_dict() if hasattr(m, "to_dict") else str(m) for m in res.mismatches],
                "output": json.loads(res.output.model_dump_json()),
                "tool_calls_summary": res.tool_calls_log.get("summary", {}),
            }
            formatted = json.dumps(payload, indent=2, sort_keys=True)
            if getattr(args, "out", None):
                out_dir = os.path.dirname(os.path.abspath(args.out))
                if out_dir:
                    os.makedirs(out_dir, exist_ok=True)
                with open(args.out, "w", encoding="utf-8") as f:
                    f.write(formatted)
            print(_safe_sanitize(formatted))
            return 1 if (res.ref_check_status != "PASS" and getattr(args, "strict_ref_check", False)) else 0
    except Exception as e:
        print(_safe_sanitize(f"LỖI investigate: {e}"), file=sys.stderr)
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
    pe.add_argument("--chain-id", type=int, default=None, help="Chọn source chain khi DB chứa nhiều chain")
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
    pa.add_argument("--allow-unfinalized", action="store_true")
    pa.add_argument("--allow-gaps", action="store_true")
    pa.add_argument("--allow-integrity-failed", action="store_true")
    pa.add_argument("--allow-commit-mismatch", action="store_true")
    pa.add_argument("--reason", choices=sorted(onchain.REASONS))
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
    pvo.add_argument("--anchor-chain-id", type=int, default=None)
    pvo.add_argument("--legacy-case-encoding", action="store_true", default=False,
                     help="Sử dụng mã hóa case_id kế thừa (raw bytes32 thay vì SHA-256)")
    pvo.set_defaults(func=cli_verify_onchain)

    # 9. reconcile
    prc = sub.add_parser("reconcile", help="Đối soát trạng thái operation on-chain ở chế độ read-only")
    prc.add_argument("--operation-id", required=True, help="Định danh operation cần đối soát")
    prc.add_argument("--db", default=None, help="Đường dẫn database SQLite")
    prc.add_argument("--rpc-url", default=None, help="RPC URL")
    prc.add_argument("--tx-hash", default=None, help="Mã băm giao dịch (tx_hash) tùy chọn override")
    prc.set_defaults(func=cli_reconcile)

    # 10. migrate-db
    pmig = sub.add_parser("migrate-db", help="Thực hiện migration cơ sở dữ liệu SQLite lên schema Group 3 một cách chủ động")
    pmig.add_argument("--db", default=None, help="Đường dẫn database SQLite cần migrate")
    pmig.set_defaults(func=cli_migrate_db)

    # 11. analyze
    pan = sub.add_parser("analyze", help="Phân tích bất thường giao dịch bằng Rule Engine (Rules R1-R4)")
    pan.add_argument("--db", default=None, help="Đường dẫn database SQLite")
    pan.add_argument("--chain-id", type=int, default=1, help="Chain ID cần phân tích (mặc định: 1)")
    pan.add_argument("--start-block", type=int, default=None, help="Block bắt đầu phân tích (test window)")
    pan.add_argument("--end-block", type=int, default=None, help="Block kết thúc phân tích (test window)")
    pan.add_argument("--cal-start-block", type=int, default=None, help="Block bắt đầu tập hiệu chỉnh (calibration window)")
    pan.add_argument("--cal-end-block", type=int, default=None, help="Block kết thúc tập hiệu chỉnh (calibration window)")
    pan.add_argument("--rules", nargs="+", default=None, help="Danh sách rule cần chạy (large_transfer, high_frequency, fan_in_out, rapid_pass_through)")
    pan.add_argument("--token-thresholds", default=None, help="File JSON hoặc chuỗi JSON cấu hình ngưỡng cho token ERC-20")
    pan.add_argument("--out", default=None, help="Đường dẫn file xuất kết quả (.json hoặc .csv)")
    pan.add_argument("--format", choices=["json", "csv"], default=None, help="Định dạng xuất file")
    pan.add_argument("--no-persist", action="store_false", dest="persist", default=True, help="Không lưu alerts vào SQLite")
    pan.add_argument("--anchored-manifest", "--p3-manifest", dest="anchored_manifest", help="Đọc gói chứng cứ đã neo (Chain of Custody / On-chain Registry) trực tiếp vào Rule Engine")
    pan.add_argument("--custody-contract", "--p3-contract", dest="custody_contract", help="Địa chỉ hợp đồng EvidenceRegistry on-chain")
    pan.add_argument("--custody-rpc-url", "--p3-rpc-url", dest="custody_rpc_url", help="RPC URL kết nối on-chain registry")
    pan.add_argument("--custody-chain-id", "--p3-anchor-chain-id", dest="custody_chain_id", type=int, help="Chain ID của mạng lưu ký on-chain")
    pan.add_argument("--custody-db", "--p3-custody-db", dest="custody_db", help="Đọc lịch sử custody từ SQLite (chế độ chỉ đọc)")
    pan.add_argument("--custody-require-verified", "--p3-require-verified", dest="custody_require_verified", action="store_true", help="Tùy chọn: chỉ phân tích khi xác minh on-chain khớp 100%%")
    pan.set_defaults(func=cli_analyze)

    # AI Investigator CLI Command
    pinv = sub.add_parser("investigate", help="Điều tra pháp y tự động bằng AI Investigator (Pydantic AI + Gemini Flash)")
    pinv.add_argument("--case-id", required=True, help="Mã vụ việc điều tra (ví dụ: euler-finance, curve-alchemix)")
    pinv.add_argument("--db", default=None, help="Đường dẫn database SQLite chứng cứ (chỉ đọc)")
    pinv.add_argument("--query", default=None, help="Chỉ thị điều tra tùy chọn")
    pinv.add_argument("--refs", nargs="*", default=None, help="Danh sách tham chiếu đầu vào (tx:..., alert:...)")
    pinv.add_argument("--provider", default=None, help="AI provider (gemini, test, function)")
    pinv.add_argument("--model", default=None, help="AI model (mặc định: gemini-3.8-flash)")
    pinv.add_argument("--max-steps", type=int, default=5, help="Giới hạn số bước gọi tool (mặc định: 5)")
    pinv.add_argument("--strict-ref-check", action="store_true", help="Từ chối kết quả nếu phát hiện CONTENT_MISMATCH")
    pinv.add_argument("--out", default=None, help="Đường dẫn file JSON xuất kết quả")
    pinv.set_defaults(func=cli_investigate)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
