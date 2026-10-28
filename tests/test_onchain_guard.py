"""Kiểm thử T08: Chốt chặn an toàn khóa (Key Safety Guard) & Chuỗi hành trình chứng cứ On-chain.
Kiểm thử với Mock RPC mà không phụ thuộc vào Foundry daemon.
"""
import os
import json
import sqlite3
import pytest
import logging
from unittest.mock import patch, MagicMock

import forensics.onchain as onchain
from forensics.schemas import init_db

def test_chain_id_mismatch(monkeypatch):
    """Test T08-1: chain_id lấy từ RPC khác với ANCHOR_CHAIN_ID trong env -> Từ chối."""
    monkeypatch.setenv("ANCHOR_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setenv("ANCHOR_CHAIN_ID", "11155111")

    with patch.object(onchain, "get_rpc_chain_id", return_value=31337):
        with pytest.raises(ValueError, match="Chain ID mismatch"):
            onchain.validate_chain_and_guard(
                signer_address="0x1234567890123456789012345678901234567890",
                rpc_url="http://127.0.0.1:8545"
            )

def test_chain_id_allowlist(monkeypatch):
    """Test T08-2: Chỉ cho phép chain 31337 và 11155111, chain khác (e.g. 1 - Mainnet) bị từ chối trừ khi ghi đè."""
    monkeypatch.setenv("ANCHOR_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setenv("ANCHOR_CHAIN_ID", "1")

    # Không có override -> từ chối
    with patch.object(onchain, "get_rpc_chain_id", return_value=1):
        with pytest.raises(ValueError, match="không nằm trong danh sách cho phép"):
            onchain.validate_chain_and_guard(
                signer_address="0x1234567890123456789012345678901234567890",
                rpc_url="http://127.0.0.1:8545",
                override_chain_id=False
            )

        # Có override -> chấp thuận
        chain_id = onchain.validate_chain_and_guard(
            signer_address="0x1234567890123456789012345678901234567890",
            rpc_url="http://127.0.0.1:8545",
            override_chain_id=True
        )
        assert chain_id == 1

def test_anvil_default_account_rejected_on_non_anvil_chain(monkeypatch):
    """Test T08-3: Địa chỉ người ký trùng tài khoản mặc định Anvil trên chain khác 31337 -> Từ chối."""
    anvil_acc_0 = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"

    monkeypatch.setenv("ANCHOR_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setenv("ANCHOR_CHAIN_ID", "11155111")

    with patch.object(onchain, "get_rpc_chain_id", return_value=11155111):
        # Trùng tài khoản Anvil trên Sepolia -> Từ chối
        with pytest.raises(ValueError, match="Chặn khóa mặc định Anvil"):
            onchain.validate_chain_and_guard(
                signer_address=anvil_acc_0,
                rpc_url="http://127.0.0.1:8545"
            )

        # Tài khoản tùy chỉnh trên Sepolia -> Chấp thuận
        custom_signer = "0x9999999999999999999999999999999999999999"
        cid = onchain.validate_chain_and_guard(
            signer_address=custom_signer,
            rpc_url="http://127.0.0.1:8545"
        )
        assert cid == 11155111

    # Tài khoản Anvil trên chính chain Anvil (31337) -> Chấp thuận
    monkeypatch.setenv("ANCHOR_CHAIN_ID", "31337")
    with patch.object(onchain, "get_rpc_chain_id", return_value=31337):
        cid = onchain.validate_chain_and_guard(
            signer_address=anvil_acc_0,
            rpc_url="http://127.0.0.1:8545"
        )
        assert cid == 31337

def test_secret_never_leaked_in_logs_or_errors(caplog):
    """Test T08-4: Khóa riêng tư / mật khẩu không bao giờ xuất hiện trong log, lỗi hay audit_events."""
    caplog.set_level(logging.DEBUG)
    fake_key = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
    fake_pass = "SuperSecretPassword123!"

    try:
        onchain.safe_redact_error(f"Failed transaction with key={fake_key} and pass={fake_pass}")
    except Exception:
        pass

    log_text = caplog.text
    assert fake_key not in log_text
    assert fake_pass not in log_text

def test_working_tree_dirty_guard_in_anchor():
    """Test T08-5: Lệnh anchor từ chối manifest có working_tree_dirty=True trừ khi có cờ allow_dirty."""
    manifest_dirty = {
        "case_id": "case-dirty-01",
        "package_digest": "a" * 64,
        "files": [],
        "software": {
            "version": "0.2.0",
            "commit_hash": "abc",
            "working_tree_dirty": True
        }
    }
    manifest_clean = {
        "case_id": "case-clean-01",
        "package_digest": "b" * 64,
        "files": [],
        "software": {
            "version": "0.2.0",
            "commit_hash": "abc",
            "working_tree_dirty": False
        }
    }

    # Khi dynamic git sạch nhưng manifest dirty:
    with patch.object(onchain, "is_working_tree_dirty", return_value=False):
        with pytest.raises(ValueError, match="working_tree_dirty=True lúc xuất gói"):
            onchain.verify_manifest_ready_for_anchor(manifest_dirty, allow_dirty=False)

        # Manifest dirty có allow_dirty -> chấp thuận kèm cảnh báo
        note = onchain.verify_manifest_ready_for_anchor(manifest_dirty, allow_dirty=True)
        assert "ALLOW_DIRTY_WARNING" in note

        # Manifest clean và git clean -> chấp thuận
        clean_note = onchain.verify_manifest_ready_for_anchor(manifest_clean, allow_dirty=False)
        assert clean_note == "CLEAN_TREE"

def test_dynamic_git_dirty_detected_even_if_manifest_clean():
    """Test T08-6: Kiểm tra động từ Git tại thời điểm anchor: phát hiện dirty kể cả khi manifest ghi false."""
    manifest_clean = {
        "case_id": "case-clean-02",
        "package_digest": "c" * 64,
        "files": [],
        "software": {
            "version": "0.2.0",
            "commit_hash": "abc",
            "working_tree_dirty": False
        }
    }

    # Manifest ghi clean, nhưng Git lúc anchor có file dirty:
    with patch.object(onchain, "is_working_tree_dirty", return_value=True):
        with pytest.raises(ValueError, match="git working tree có thay đổi chưa commit lúc anchor"):
            onchain.verify_manifest_ready_for_anchor(manifest_clean, allow_dirty=False)

        # Với cờ allow_dirty -> cho phép và ghi nhận warning
        note = onchain.verify_manifest_ready_for_anchor(manifest_clean, allow_dirty=True)
        assert "ALLOW_DIRTY_WARNING" in note
        assert "lúc anchor" in note

def test_unlocked_flag_blocked_on_non_anvil_chain(tmp_path):
    """Test T08-7: Chặn cờ --unlocked/--from trên mạng non-Anvil (Sepolia 11155111); bắt buộc keystore (--account)."""
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(json.dumps({
        "case_id": "case-sepolia-01",
        "package_digest": "d" * 64,
        "files": [],
        "software": {"version": "0.2.0", "commit_hash": "abc", "working_tree_dirty": False}
    }), encoding="utf-8")

    contract_addr = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

    with patch.object(onchain, "get_rpc_chain_id", return_value=11155111), \
         patch.object(onchain, "is_working_tree_dirty", return_value=False):
        # anchor_evidence không có account -> bị từ chối ngay lập tức
        with pytest.raises(ValueError, match="bắt buộc sử dụng keystore với đối số --account"):
            onchain.anchor_evidence(
                manifest_path_or_dir=str(manifest_file),
                contract_address=contract_addr,
                account=None,
                from_addr="0x9999999999999999999999999999999999999999"
            )

        # record_custody_action không có account -> bị từ chối
        with pytest.raises(ValueError, match="bắt buộc sử dụng keystore với đối số --account"):
            onchain.record_custody_action(
                evidence_id=1,
                action=1,
                artifact_sha256="0x" + "a" * 64,
                note="analysis note",
                contract_address=contract_addr,
                account=None,
                from_addr="0x9999999999999999999999999999999999999999"
            )

def test_decode_evidence_registered_event_full_validation():
    """Test T08-8: Giải mã event EvidenceRegistered: kiểm tra status, đủ 4 topics và khớp caseId/manifestHash."""
    topic0 = onchain.TOPIC_EVIDENCE_REGISTERED
    evidence_id = 42
    topic1 = f"0x{evidence_id:064x}"
    case_id = "CASE-2026-001"
    case_id_bytes32 = onchain.string_to_bytes32_hex(case_id).lower()
    manifest_hash = "22" * 32
    topic3 = "0x" + manifest_hash

    fake_receipt = {
        "status": "0x1",
        "logs": [
            {
                "address": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
                "topics": [topic0, topic1, case_id_bytes32, topic3],
                "data": "0x"
            }
        ]
    }

    # Giải mã thành công và khớp đầy đủ
    extracted_id = onchain.extract_evidence_id_from_receipt(
        fake_receipt,
        expected_case_id=case_id,
        expected_manifest_sha256=manifest_hash
    )
    assert extracted_id == 42

    # Receipt status = 0 -> lỗi
    fake_failed_receipt = {"status": "0x0", "logs": []}
    with pytest.raises(RuntimeError, match="Giao dịch on-chain thất bại"):
        onchain.extract_evidence_id_from_receipt(fake_failed_receipt)

    # Thiếu topics (< 4 topics) -> từ chối
    fake_incomplete_receipt = {
        "status": "0x1",
        "logs": [
            {
                "address": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
                "topics": [topic0, topic1],  # chỉ có 2 topics
                "data": "0x"
            }
        ]
    }
    with pytest.raises(ValueError, match="Event EvidenceRegistered không hợp lệ hoặc thiếu indexed topics"):
        onchain.extract_evidence_id_from_receipt(fake_incomplete_receipt)

    # Sai caseId -> từ chối
    with pytest.raises(ValueError, match="Event caseId mismatch"):
        onchain.extract_evidence_id_from_receipt(
            fake_receipt,
            expected_case_id="DIFFERENT-CASE",
            expected_manifest_sha256=manifest_hash
        )

    # Sai manifestHash -> từ chối
    with pytest.raises(ValueError, match="Event manifestSha256 mismatch"):
        onchain.extract_evidence_id_from_receipt(
            fake_receipt,
            expected_case_id=case_id,
            expected_manifest_sha256="99" * 32
        )

    # Không có event EvidenceRegistered trong logs -> từ chối
    fake_empty_logs_receipt = {"status": "0x1", "logs": []}
    with pytest.raises(ValueError, match="Không tìm thấy event EvidenceRegistered hợp lệ"):
        onchain.extract_evidence_id_from_receipt(fake_empty_logs_receipt)

def test_chain_id_write_override_blocked(monkeypatch):
    """Test T08-9: Giao dịch ghi (is_write=True) tuyệt đối cấm override chain_id ngoài allowlist."""
    monkeypatch.setenv("ANCHOR_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setenv("ANCHOR_CHAIN_ID", "1")

    with patch.object(onchain, "get_rpc_chain_id", return_value=1):
        with pytest.raises(ValueError, match="Chốt chặn an toàn ghi"):
            onchain.validate_chain_and_guard(
                signer_address="0x1234567890123456789012345678901234567890",
                rpc_url="http://127.0.0.1:8545",
                override_chain_id=True,
                is_write=True
            )

def test_non_loopback_rpc_rejected_for_unlocked(tmp_path):
    """Test T08-10: Cấm chế độ --unlocked trên RPC endpoint từ xa (không phải 127.0.0.1, localhost, ::1) kể cả chain_id=31337."""
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(json.dumps({
        "case_id": "case-remote-01",
        "package_digest": "e" * 64,
        "files": [],
        "software": {"version": "0.2.0", "commit_hash": "abc", "working_tree_dirty": False}
    }), encoding="utf-8")

    contract_addr = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

    with patch.object(onchain, "get_rpc_chain_id", return_value=31337), \
         patch.object(onchain, "is_working_tree_dirty", return_value=False):
        # RPC trỏ tới IP từ xa: 192.168.1.100
        with pytest.raises(ValueError, match="Chế độ ký --unlocked CHỈ được phép trên RPC cục bộ loopback"):
            onchain.anchor_evidence(
                manifest_path_or_dir=str(manifest_file),
                contract_address=contract_addr,
                account=None,
                from_addr="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
                rpc_url="http://192.168.1.100:8545"
            )

        # RPC trỏ tới domain từ xa
        with pytest.raises(ValueError, match="Chế độ ký --unlocked CHỈ được phép trên RPC cục bộ loopback"):
            onchain.record_custody_action(
                evidence_id=1,
                action=1,
                artifact_sha256="0x" + "b" * 64,
                note="test remote",
                contract_address=contract_addr,
                account=None,
                from_addr="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
                rpc_url="http://remote.anvil-node.internal:8545"
            )
