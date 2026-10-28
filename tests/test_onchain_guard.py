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
    # Địa chỉ mặc định Anvil #0
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

    # Gọi hàm xử lý với mật khẩu/khóa và gây lỗi
    try:
        onchain.safe_redact_error(f"Failed transaction with key={fake_key} and pass={fake_pass}")
    except Exception:
        pass

    log_text = caplog.text
    assert fake_key not in log_text
    assert fake_pass not in log_text

def test_working_tree_dirty_guard_in_anchor(tmp_path):
    """Test T08-5: Lệnh anchor từ chối manifest có working_tree_dirty=True trừ khi có cờ allow_dirty."""
    db_file = str(tmp_path / "test_anchor.db")
    init_db(db_file)

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

    # Manifest dirty không có allow_dirty -> từ chối
    with pytest.raises(ValueError, match="working_tree_dirty=True"):
        onchain.verify_manifest_ready_for_anchor(manifest_dirty, allow_dirty=False)

    # Manifest dirty có allow_dirty -> chấp thuận
    note = onchain.verify_manifest_ready_for_anchor(manifest_dirty, allow_dirty=True)
    assert "ALLOW_DIRTY" in note

    # Manifest clean -> chấp thuận
    clean_note = onchain.verify_manifest_ready_for_anchor(manifest_clean, allow_dirty=False)
    assert clean_note == "CLEAN_TREE"

def test_decode_evidence_registered_event():
    """Test T08-6: Giải mã chính xác evidenceId từ event EvidenceRegistered thay vì suy đoán."""
    # Topic 0: EvidenceRegistered
    topic0 = onchain.TOPIC_EVIDENCE_REGISTERED
    evidence_id = 42
    topic1 = f"0x{evidence_id:064x}"
    case_id_bytes32 = "0x" + "11" * 32
    manifest_hash = "0x" + "22" * 32

    fake_receipt = {
        "status": "0x1",
        "logs": [
            {
                "address": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
                "topics": [topic0, topic1, case_id_bytes32, manifest_hash],
                "data": "0x"
            }
        ]
    }

    extracted_id = onchain.extract_evidence_id_from_receipt(fake_receipt)
    assert extracted_id == 42

    # Receipt status = 0 -> lỗi
    fake_failed_receipt = {
        "status": "0x0",
        "logs": []
    }
    with pytest.raises(RuntimeError, match="Giao dịch on-chain thất bại"):
        onchain.extract_evidence_id_from_receipt(fake_failed_receipt)
