"""D1: independently validate both trusted anchor-chain configuration sources."""
import pytest
from unittest.mock import Mock
from test_integrity_2a import sample
from test_onchain_2b import flow, CONTRACT
from forensics import onchain as oc
from forensics.cli import build_parser, cli_verify_onchain


@pytest.mark.parametrize('environment,argument,status,code',[
    ('11155111',31337,'ERROR','ANCHOR_CONTEXT_CONFLICT'),
    ('31337',31337,'MATCH','OK'),
    ('031337',31337,'MATCH','OK'),
    ('31337',None,'MATCH','OK'),
    (None,31337,'MATCH','OK'),
    (None,None,'ERROR','ANCHOR_CONTEXT_REQUIRED'),
    ('bad',31337,'ERROR','ANCHOR_CONTEXT_INVALID'),
    ('',31337,'ERROR','ANCHOR_CONTEXT_INVALID'),
    ('-1',31337,'ERROR','ANCHOR_CONTEXT_INVALID'),
    ('0',31337,'ERROR','ANCHOR_CONTEXT_INVALID'),
    ('31337 ',31337,'ERROR','ANCHOR_CONTEXT_INVALID'),
    ('0x7a69',31337,'ERROR','ANCHOR_CONTEXT_INVALID'),
    ('bad',None,'ERROR','ANCHOR_CONTEXT_INVALID'),
    ('31337',True,'ERROR','ANCHOR_CONTEXT_INVALID'),
    ('31337',-1,'ERROR','ANCHOR_CONTEXT_INVALID'),
])
def test_d1_context_sources(flow,monkeypatch,environment,argument,status,code):
    if environment is None:monkeypatch.delenv('ANCHOR_CHAIN_ID',raising=False)
    else:monkeypatch.setenv('ANCHOR_CHAIN_ID',environment)
    wallet=Mock(side_effect=AssertionError('Wallet must not be accessed'))
    monkeypatch.setattr(oc,'resolve_signer',wallet)
    monkeypatch.setattr(oc,'prepare_write',wallet)
    network=Mock(wraps=flow['network']);monkeypatch.setattr(oc,'rpc_read',network)
    result=oc.verify_onchain_evidence(str(flow['pkg']),CONTRACT,anchor_chain_id=argument)
    assert (result.status,result.reason_code)==(status,code)
    assert result.exit_code==(0 if status=='MATCH' else 2)
    wallet.assert_not_called();flow['sent'].assert_not_called()
    if status=='ERROR':network.assert_not_called()


def test_d1_cli_conflict_exit_two(flow,monkeypatch,capsys):
    monkeypatch.setenv('ANCHOR_CHAIN_ID','11155111')
    args=build_parser().parse_args(['verify-onchain',str(flow['pkg']),'--contract',CONTRACT,
                                  '--anchor-chain-id','31337'])
    assert cli_verify_onchain(args)==2
    captured=capsys.readouterr()
    assert 'ERROR: ANCHOR_CONTEXT_CONFLICT' in captured.err
    assert 'MATCH' not in captured.out


def test_d1_invalid_environment_does_not_echo_canary(flow,monkeypatch,capsys,caplog):
    canary='D1_PRIVATE_PASSWORD_CANARY'
    monkeypatch.setenv('ANCHOR_CHAIN_ID',canary)
    result=oc.verify_onchain_evidence(str(flow['pkg']),CONTRACT,anchor_chain_id=31337)
    assert result.exit_code==2 and result.reason_code=='ANCHOR_CONTEXT_INVALID'
    captured=capsys.readouterr()
    assert canary not in repr(result)+captured.out+captured.err+caplog.text


def test_d1e1_overlong_numeric_environment(flow,monkeypatch,capsys,caplog):
    value='0'*5000
    monkeypatch.setenv('ANCHOR_CHAIN_ID',value)
    network=Mock(wraps=flow['network']);monkeypatch.setattr(oc,'rpc_read',network)
    result=oc.verify_onchain_evidence(str(flow['pkg']),CONTRACT,anchor_chain_id=31337)
    assert (result.status,result.exit_code,result.reason_code)==('ERROR',2,'ANCHOR_CONTEXT_INVALID')
    captured=capsys.readouterr()
    assert value not in repr(result)+captured.out+captured.err+caplog.text
    network.assert_not_called();flow['sent'].assert_not_called()
