"""Group 1: only mocked RPC/send; optional cast address derivation is offline."""
import json
import logging
import shutil
import sqlite3
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from forensics import onchain as oc
from forensics.schemas import init_db
from test_evidence_p2 import populate_sample_db
from forensics.evidence import export_evidence
from test_onchain_2b import complete_receipt, registry_reply

DEFAULTS = [
    '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266',
    '0x70997970c51812dc3a010c7d01b50e0d17dc79c8',
    '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc',
    '0x90f79bf6eb2c4f870365e785982e1f101e93b906',
    '0x15d34aaf54267db7d7c367839aaf71a00a2c6a65',
    '0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc',
    '0x976ea74026e726554db657fa54763abd0c3a0aa9',
    '0x14dc79964da2c08b23698b3d3cc7ca32193d9955',
    '0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f',
    '0xa0ee7a142d267c1f36714e4a8f75612f20a79720',
]
SIGNER = '0x' + '9' * 40
CONTRACT = '0x' + '8' * 40
TX = '0x' + '7' * 64


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    for key in ('ANCHOR_FROM', 'ANCHOR_CHAIN_ID', 'ANCHOR_RPC_URL'):
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def write_flow(tmp_path, monkeypatch):
    db = tmp_path / 'events.db'
    populate_sample_db(str(db),3)
    package=tmp_path/'package'
    export_evidence('guard-case',0,2,str(package),str(db))
    manifest=package/'manifest.json'
    monkeypatch.setattr(oc, 'is_working_tree_dirty', lambda: False)
    monkeypatch.setattr(oc, 'get_rpc_chain_id', lambda url: 31337)
    def network(url,method,params):
        if method=='web3_clientVersion':return 'anvil/v1.0'
        if method=='eth_getBlockByNumber':return {'hash':'0x'+'6'*64}
        if method=='eth_call':return registry_reply('guard-case',oc.compute_file_sha256(str(manifest)),SIGNER)
        return '0x6000'
    monkeypatch.setattr(oc,'rpc_read',Mock(side_effect=network))
    monkeypatch.setattr(oc, '_run_cast', Mock(return_value=SIGNER))
    send = Mock(return_value=json.dumps({'transactionHash': TX}))
    monkeypatch.setattr(oc, 'run_cast_send', send)
    receipt = complete_receipt(CONTRACT,SIGNER,TX,'guard-case',oc.compute_file_sha256(str(manifest)))
    monkeypatch.setattr(oc, 'get_transaction_receipt', Mock(return_value=receipt))

    def invoke(kind, **kwargs):
        options = dict(contract_address=CONTRACT, db_path=str(db), account='investigator',
                       rpc_url='http://127.0.0.1:8545')
        options.update(kwargs)
        if kind == 'anchor':
            return oc.anchor_evidence(str(manifest), allow_dirty=True, allow_unfinalized=True, reason='controlled-test', **options)
        receipt['logs'][0].update(topics=[oc.TOPIC_CUSTODY_RECORDED,f'0x{1:064x}',f'0x{1:064x}','0x'+'0'*24+SIGNER[2:]],
                                  data='0x'+'a'*64+oc.string_to_bytes32_hex('note')[2:])
        return oc.record_custody_action(1, 1, '0x' + 'a' * 64, 'note', **options)
    return invoke, send, receipt, db


@pytest.mark.parametrize('kind', ['anchor', 'custody'])
def test_guard_uses_keystore_signer_and_pins_chain(write_flow, monkeypatch, kind):
    invoke, send, receipt, db = write_flow
    monkeypatch.setattr(oc, 'get_rpc_chain_id', lambda url: 11155111)
    monkeypatch.setattr(oc, 'compute_anvil_default_accounts', lambda: DEFAULTS)
    invoke(kind)
    args = send.call_args.args[0]
    assert args[args.index('--chain') + 1] == '11155111'
    assert args[args.index('--account') + 1] == 'investigator'
    assert '--unlocked' not in args
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT actor_address FROM custody_events').fetchone()[0] == receipt['from']


@pytest.mark.parametrize('kind', ['anchor', 'custody'])
def test_from_must_match_keystore(write_flow, kind):
    invoke, send, _, _ = write_flow
    with pytest.raises(ValueError, match='SIGNER_MISMATCH'):
        invoke(kind, from_addr=DEFAULTS[0])
    send.assert_not_called()


@pytest.mark.parametrize('kind', ['anchor', 'custody'])
def test_anvil_keystore_cannot_bypass_guard(write_flow, monkeypatch, kind):
    invoke, send, _, _ = write_flow
    monkeypatch.setattr(oc, '_run_cast', Mock(return_value=DEFAULTS[9]))
    monkeypatch.setattr(oc, 'get_rpc_chain_id', lambda url: 11155111)
    monkeypatch.setattr(oc, 'compute_anvil_default_accounts', lambda: DEFAULTS)
    with pytest.raises(ValueError, match='Chặn khóa mặc định Anvil'):
        invoke(kind)
    send.assert_not_called()


@pytest.mark.parametrize('kind', ['anchor', 'custody'])
def test_receipt_signer_mismatch_never_updates_db(write_flow, kind):
    invoke, _, receipt, db = write_flow
    receipt['from'] = DEFAULTS[0]
    with pytest.raises(ValueError, match='RECEIPT_SIGNER_MISMATCH'):
        invoke(kind)
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT COUNT(*) FROM custody_events').fetchone()[0] == 0


@pytest.mark.parametrize('kind', ['anchor', 'custody'])
def test_unlocked_requires_anvil_client(write_flow, monkeypatch, kind):
    invoke, send, _, _ = write_flow
    monkeypatch.setattr(oc, 'rpc_read', Mock(return_value='Geth/v1.0'))
    with pytest.raises(ValueError, match='ANVIL_CLIENT_REQUIRED'):
        invoke(kind, account=None, from_addr=SIGNER)
    send.assert_not_called()


@pytest.mark.parametrize('kind', ['anchor', 'custody'])
def test_local_anvil_unlocked_pins_chain(write_flow, kind):
    invoke, send, _, _ = write_flow
    invoke(kind, account=None, from_addr=SIGNER)
    args = send.call_args.args[0]
    assert args[args.index('--chain')+1] == '31337'
    assert args[args.index('--from')+1] == SIGNER
    assert '--unlocked' in args


@pytest.mark.parametrize('kind', ['anchor', 'custody'])
def test_contract_bytecode_required(write_flow, monkeypatch, kind):
    invoke, send, _, _ = write_flow
    monkeypatch.setattr(oc, 'rpc_read', Mock(return_value='0x'))
    with pytest.raises(ValueError, match='CONTRACT_CODE_MISSING'):
        invoke(kind)
    send.assert_not_called()


@pytest.mark.parametrize('url', ['file://localhost/key', 'ftp://localhost', 'http://rpc.example/key',
                               'https://', 'https://rpc.example:bad', 'https://rpc.example/#key'])
def test_rpc_url_policy_rejects_before_network(monkeypatch, url):
    rpc = Mock()
    monkeypatch.setattr(oc, 'get_rpc_chain_id', rpc)
    with pytest.raises(ValueError, match='RPC_'):
        oc.validate_chain_and_guard(SIGNER, url)
    rpc.assert_not_called()


@pytest.mark.parametrize('url', ['http://127.0.0.1:8545', 'http://localhost', 'http://[::1]:8545',
                               'https://rpc.example/key'])
def test_rpc_url_policy_accepts(url):
    oc.validate_rpc_url(url)


@pytest.mark.parametrize('failure', ['missing', 'timeout', 'exit', 'malformed', 'duplicate'])
def test_anvil_derivation_fail_closed(monkeypatch, failure):
    fake = Mock(return_value=subprocess.CompletedProcess([], 0, DEFAULTS[0], ''))
    if failure == 'missing':
        fake.side_effect = FileNotFoundError('untrusted')
    elif failure == 'timeout':
        fake.side_effect = subprocess.TimeoutExpired(['untrusted'], 5)
    elif failure == 'exit':
        fake.return_value.returncode = 1
    elif failure == 'malformed':
        fake.return_value.stdout = '0x123'
    monkeypatch.setattr(oc.subprocess, 'run', fake)
    monkeypatch.setattr(oc, 'get_rpc_chain_id', lambda url: 11155111)
    with pytest.raises(RuntimeError, match='ANVIL_ACCOUNTS_UNAVAILABLE'):
        oc.validate_chain_and_guard(SIGNER, 'https://rpc.example', is_write=True)


def test_anvil_accounts_match_cast():
    if not (Path(oc.CAST_BIN).is_file() or shutil.which(oc.CAST_BIN)):
        pytest.skip('cast unavailable; failure paths tested separately')
    assert oc.compute_anvil_default_accounts() == DEFAULTS


@pytest.mark.parametrize('index', range(10))
def test_all_default_accounts_blocked_normalized(monkeypatch, index):
    monkeypatch.setattr(oc, 'compute_anvil_default_accounts', lambda: DEFAULTS)
    monkeypatch.setattr(oc, 'get_rpc_chain_id', lambda url: 11155111)
    with pytest.raises(ValueError, match='Chặn khóa mặc định Anvil'):
        oc.validate_chain_and_guard(DEFAULTS[index][2:].upper(), 'https://rpc.example')


def test_keystore_command_is_safe_and_clears_inherited_signer(monkeypatch):
    fake = Mock(return_value=subprocess.CompletedProcess([], 0, SIGNER, ''))
    monkeypatch.setattr(oc.subprocess, 'run', fake)
    monkeypatch.setenv('ETH_FROM', DEFAULTS[0])
    assert oc.resolve_signer('investigator', 'password-file.txt') == SIGNER
    args, kwargs = fake.call_args
    assert args[0] == [oc.CAST_BIN, 'wallet', 'address', '--account', 'investigator',
                       '--password-file', 'password-file.txt']
    assert kwargs['shell'] is False and kwargs['timeout'] == 30
    assert 'ETH_FROM' not in kwargs['env']


@pytest.mark.parametrize('kind', ['send', 'call', 'wallet'])
@pytest.mark.parametrize('failure', ['exit', 'timeout', 'exception'])
def test_cast_errors_never_expose_secrets(monkeypatch, capsys, caplog, tmp_path, kind, failure):
    secrets = ['0x' + 'ab' * 32, 'cd' * 32, 'fake-password!42',
               'alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima']
    untrusted = ' '.join(secrets)
    fake = Mock(return_value=subprocess.CompletedProcess([], 17, untrusted, untrusted))
    if failure == 'timeout':
        fake.side_effect = subprocess.TimeoutExpired([untrusted], 30, output=untrusted, stderr=untrusted)
    elif failure == 'exception':
        fake.side_effect = OSError(untrusted)
    monkeypatch.setattr(oc.subprocess, 'run', fake)
    caplog.set_level(logging.DEBUG)
    db = tmp_path / 'audit.db'
    conn = init_db(str(db))
    with pytest.raises(RuntimeError) as caught:
        if kind == 'wallet':
            oc.resolve_signer('investigator')
        else:
            getattr(oc, 'run_cast_' + kind)(['--rpc-url', 'http://localhost'])
    captured = capsys.readouterr()
    visible = str(caught.value) + captured.out + captured.err + caplog.text
    assert caught.value.__suppress_context__ or failure == 'exit'
    assert 'CAST_' in visible
    for secret in secrets:
        assert secret not in visible
        assert all(secret not in str(row) for row in conn.execute('SELECT * FROM audit_events'))
    assert conn.execute('SELECT COUNT(*) FROM audit_events').fetchone()[0] == 0
    conn.close()
    args, kwargs = fake.call_args
    assert kwargs['shell'] is False and kwargs['timeout'] == 30
    assert '--private-key' not in args[0] and '--password' not in args[0]
    assert all(secret not in ' '.join(args[0]) for secret in secrets)


def test_rpc_errors_do_not_echo_provider_secrets(monkeypatch):
    opener = Mock()
    opener.open.side_effect = OSError('https://provider.invalid/fake-api-secret')
    monkeypatch.setattr(oc.urllib.request, 'build_opener', Mock(return_value=opener))
    with pytest.raises(RuntimeError, match='RPC_QUERY_FAILED') as caught:
        oc.rpc_read('https://provider.invalid/fake-api-secret', 'eth_chainId', [])
    assert 'fake-api-secret' not in str(caught.value)
