"""B01-B08/C01-C12: actual package verification; fake network only in unit tests."""
import json
import copy
import hashlib
import sqlite3
import subprocess
from pathlib import Path
from unittest.mock import Mock
import pytest
from test_integrity_2a import sample, exported
from test_integrity_2a import rehash
from test_provenance_2a import repo, command, commit
from forensics import provenance
from forensics.integrity import verify_package, raw_hash
from forensics import onchain as oc

CONTRACT='0x'+'8'*40
SIGNER='0x'+'9'*40

def abi_uri(uri):
    raw=uri.encode()
    return f'{len(raw):064x}'+raw.hex()+('00'*((-len(raw))%32))

def registration_data(signer,uri):
    return '0x'+'0'*24+signer[2:]+f'{64:064x}'+abi_uri(uri)

def complete_receipt(contract,signer,tx,case,digest):
    receipt={'from':signer,'to':contract,'status':'0x1','transactionHash':tx,
             'blockHash':'0x'+'6'*64,'blockNumber':'0x1','transactionIndex':'0x0'}
    receipt['logs']=[dict({k:receipt[k] for k in ('transactionHash','blockHash','blockNumber','transactionIndex')},
        address=contract,logIndex='0x0',removed=False,topics=[oc.TOPIC_EVIDENCE_REGISTERED,f'0x{1:064x}',
        oc.string_to_bytes32_hex(case),'0x'+digest],data=registration_data(signer,f'evidence://{case}/manifest.json'))]
    return receipt

def registry_reply(case,digest,signer):
    return '0x'+f'{32:064x}{1:064x}'+oc.string_to_bytes32_hex(case)[2:]+digest+f'{224:064x}'+('0'*24)+signer[2:]+f'{1:064x}{1:064x}'+abi_uri(f'evidence://{case}/manifest.json')

def test_B01_anchor_rejects_tampered_payload_before_send(tmp_path,sample,monkeypatch):
    pkg=exported(tmp_path,sample)
    (pkg/'timeline.csv').write_text('tampered')
    monkeypatch.setattr(oc,'verify_manifest_ready_for_anchor',lambda *a,**k:'CLEAN_TREE')
    monkeypatch.setattr(oc,'prepare_write',lambda *a,**k:(SIGNER,31337))
    send=Mock(side_effect=RuntimeError('TEST_SEND_REACHED'))
    monkeypatch.setattr(oc,'run_cast_send',send)
    with pytest.raises((ValueError,RuntimeError)):
        oc.anchor_evidence(str(pkg),CONTRACT,db_path=str(sample))
    send.assert_not_called()

def test_B06_verify_rejects_payload_even_when_registry_matches(tmp_path,sample,monkeypatch):
    pkg=exported(tmp_path,sample)
    (pkg/'timeline.csv').write_text('tampered')
    call=Mock(return_value='true\n'+SIGNER+'\n1')
    monkeypatch.setattr(oc,'run_cast_call',call)
    result=oc.verify_onchain_evidence(str(pkg),CONTRACT,evidence_id=1)
    ok,_=result
    assert not ok
    call.assert_not_called()

@pytest.mark.parametrize('mutation',['extra_topic','bool_status','malformed_data'])
def test_B05_event_rejects_invalid_shape(mutation):
    receipt={'status':'0x1','logs':[{'address':CONTRACT,'topics':[
        oc.TOPIC_EVIDENCE_REGISTERED,'0x'+'0'*63+'1',
        oc.string_to_bytes32_hex('case'),'0x'+'a'*64],'data':'0x'}]}
    if mutation=='extra_topic':receipt['logs'][0]['topics'].append('0x'+'0'*64)
    if mutation=='bool_status':receipt['status']=True
    with pytest.raises((ValueError,RuntimeError)):
        oc.extract_evidence_id_from_receipt(receipt)

@pytest.fixture
def flow(tmp_path,sample,monkeypatch,request):
    if getattr(request,'param',31337)!=31337:
        with sqlite3.connect(sample) as conn:
            for table in ('blocks','transactions','receipts','logs','asset_transfers','collector_runs'):
                conn.execute('UPDATE '+table+' SET chain_id=?',(request.param,))
    pkg=exported(tmp_path,sample);digest=oc.compute_file_sha256(pkg/'manifest.json')
    tx='0x'+'7'*64
    receipt=complete_receipt(CONTRACT,SIGNER,tx,'test-2a',digest)
    chain=[31337]
    monkeypatch.setattr(oc,'get_rpc_chain_id',lambda url:chain[0])
    monkeypatch.setattr(oc,'prepare_write',lambda *a,**k:(SIGNER,chain[0]))
    monkeypatch.setattr(oc,'get_transaction_receipt',lambda *a:receipt)
    def network(url,method,params):
        if method=='eth_getCode':return '0x6000'
        if method=='eth_getLogs':return receipt['logs']
        if method=='eth_getTransactionByHash':return dict(hash=tx,to=CONTRACT,**{'from':SIGNER},chainId=hex(chain[0]))
        if method=='eth_getBlockByNumber':
            n=1 if params[0]=='latest' else int(params[0],16)
            return dict(hash=receipt['blockHash'],number=hex(n),timestamp=hex(n))
        if method=='eth_call':
            data=params[0]['data']
            if data.startswith('0x5a9535b7'):return f'0x{1:064x}'
            if data.startswith('0x9fcc7309'):return f'0x{1:064x}'+'0'*24+SIGNER[2:]+f'{1:064x}'
            return registry_reply('test-2a',digest,SIGNER)
        raise AssertionError('Unexpected RPC method')
    monkeypatch.setattr(oc,'rpc_read',network)
    audit=[]
    def send(args):
        with sqlite3.connect(sample) as conn:
            rows=conn.execute("SELECT metadata FROM audit_events WHERE action='ANCHOR_PREFLIGHT'").fetchall()
        assert rows,'Audit not committed before send'
        audit.append(json.loads(rows[-1][0]))
        return json.dumps({'transactionHash':tx})
    sent=Mock(side_effect=send);monkeypatch.setattr(oc,'run_cast_send',sent)
    def invoke(**kwargs):
        opts=dict(db_path=str(sample),rpc_url='http://127.0.0.1:8545',allow_dirty=True,
                  allow_unfinalized=True,reason='controlled-test')
        opts.update(kwargs)
        return oc.anchor_evidence(str(pkg),CONTRACT,**opts)
    return dict(pkg=pkg,db=sample,receipt=receipt,sent=sent,invoke=invoke,chain=chain,audit=audit,network=network)

def test_B03_C08_audit_committed_before_send(flow):
    result=flow['invoke']()
    assert result['evidence_id']==1 and flow['sent'].call_count==1
    assert flow['audit'][0]['reason']=='controlled-test'
    assert flow['audit'][0]['anchor_chain_id']==31337

@pytest.mark.parametrize('problem',['missing','locked','insert','commit'])
def test_B03_C08_audit_failure_never_sends(flow,tmp_path,monkeypatch,problem):
    opts={};lock=None
    if problem=='missing':opts['db_path']=str(tmp_path/'absent.db')
    elif problem=='locked':
        lock=sqlite3.connect(flow['db']);lock.execute('BEGIN EXCLUSIVE')
    else:
        real_connect=sqlite3.connect
        class Broken:
            def __init__(self,*a,**k):self.conn=real_connect(*a,**k)
            def execute(self,*a):
                if problem=='insert':raise sqlite3.OperationalError('fake-password')
                return self.conn.execute(*a)
            def commit(self):raise sqlite3.OperationalError('fake-password')
            def close(self):self.conn.close()
        monkeypatch.setattr(oc.sqlite3,'connect',Broken)
    try:
        with pytest.raises((ValueError,RuntimeError)):flow['invoke'](**opts)
        flow['sent'].assert_not_called()
    finally:
        if lock:lock.close()

@pytest.mark.parametrize('reason',[None,'',' ', 'fake-password','https://provider.invalid/token'])
def test_B02_B07_C06_reason_rejected_without_echo(flow,reason,capsys,caplog):
    with pytest.raises(ValueError) as caught:flow['invoke'](reason=reason)
    flow['sent'].assert_not_called()
    assert str(caught.value) in ('REASON_REQUIRED','REASON_INVALID')
    assert not capsys.readouterr().out and not caplog.text

@pytest.mark.parametrize('override',[False,True])
def test_B02_C09_synthetic_public_no_bypass(flow,override):
    m=json.loads((flow['pkg']/'manifest.json').read_text());r=oc.package_preflight(flow['pkg'])
    # Policy input is validated context; synthetic true does not depend on source chain number.
    r.context['synthetic']=True
    flags=dict(allow_dirty=True,allow_unfinalized=True,allow_gaps=True,
               allow_integrity_failed=override,allow_commit_mismatch=True)
    with pytest.raises(ValueError,match='SYNTHETIC_PUBLIC_FORBIDDEN'):
        oc.check_anchor_policy(r,provenance.inspect_commit_provenance(m['export_commit']),11155111,flags,'controlled-test')

def test_C10_integrity_declaration_diagnostic_never_upgrades(flow):
    path=flow['pkg']/'manifest.json';m=json.loads(path.read_text())
    m['integrity_checks']['verify_local'].update(status='FAILED',mismatches=1)
    path.write_text(json.dumps(m),encoding='utf-8')
    assert verify_package(flow['pkg']).status=='INVALID'
    r=oc.package_preflight(flow['pkg'],True)
    assert r.status=='INVALID' and r.coverage=='LIMITED' and r.details['declaration_failed']
    with pytest.raises(ValueError):oc.package_preflight(flow['pkg'])
    flags=dict(allow_dirty=True,allow_unfinalized=True,allow_gaps=False,allow_integrity_failed=True,allow_commit_mismatch=False)
    p=provenance.inspect_commit_provenance(m['export_commit'])
    assert 'allow_integrity_failed' in oc.check_anchor_policy(r,p,31337,flags,'controlled-test')['applied_exceptions']
    with pytest.raises(ValueError,match='INTEGRITY_OVERRIDE_LOCAL_ONLY'):
        oc.check_anchor_policy(r,p,11155111,flags,'controlled-test')

@pytest.mark.parametrize('corruption',['hash','digest','receipt','derived','structure','extra','declaration_shape','finalization'])
def test_B01_C11_no_flag_bypasses_independent_validation(flow,corruption):
    pkg=flow['pkg'];path=pkg/'manifest.json';m=json.loads(path.read_text())
    m['integrity_checks']['verify_local'].update(status='FAILED',mismatches=1)
    if corruption=='hash':(pkg/'timeline.csv').write_text('changed')
    if corruption=='digest':m['package_digest']='f'*64
    if corruption=='structure':m.pop('files')
    if corruption=='extra':(pkg/'extra.txt').write_text('extra')
    if corruption=='declaration_shape':m['integrity_checks']['verify_local']['mismatches']=True
    if corruption=='finalization':m['finalization']['is_finalized']=not m['finalization']['is_finalized']
    path.write_text(json.dumps(m),encoding='utf-8')
    if corruption=='receipt':
        f=pkg/'raw_receipts.jsonl';rows=[json.loads(x) for x in f.read_text().splitlines()]
        rows[0]['raw_json'].pop('gasUsed');rows[0]['raw_sha256']=raw_hash(rows[0]['raw_json'])
        f.write_text(''.join(json.dumps(r)+'\n' for r in rows));rehash(pkg)
    if corruption=='derived':
        f=pkg/'asset_transfers.csv';f.write_text(f.read_text().replace('1000000000000000000','999'));rehash(pkg)
    with pytest.raises((ValueError,RuntimeError)):
        flow['invoke'](allow_integrity_failed=True,allow_gaps=True,allow_commit_mismatch=True)
    flow['sent'].assert_not_called()

@pytest.mark.parametrize('status',['MISSING','MALFORMED','WRONG_OBJECT_TYPE','WRONG_REPOSITORY','INDETERMINATE'])
def test_C07_non_overridable_provenance(flow,monkeypatch,status):
    p=provenance.inspect_commit_provenance(oc.package_preflight(flow['pkg']).context['export_commit']);p['status']=status
    monkeypatch.setattr(oc,'inspect_commit_provenance',lambda *a:p)
    with pytest.raises((ValueError,RuntimeError)):
        flow['invoke'](allow_commit_mismatch=True,allow_integrity_failed=True,allow_gaps=True)
    flow['sent'].assert_not_called()

def test_C04_C05_C06_real_git_ancestry(repo,flow,monkeypatch):
    first=command(repo,'rev-parse','HEAD')
    assert provenance.inspect_commit_provenance(first,repo)['status']=='OK'
    command(repo,'checkout','-qb','left');(repo/'left').write_text('left');left=commit(repo,'left')
    command(repo,'checkout','-qb','right',first);(repo/'right').write_text('right');commit(repo,'right')
    assert provenance.inspect_commit_provenance(first,repo)['status']=='OK'
    p=provenance.inspect_commit_provenance(left,repo)
    assert p['status']=='EXISTING_NON_ANCESTOR'
    monkeypatch.setattr(oc,'inspect_commit_provenance',lambda *a:p)
    with pytest.raises(ValueError,match='POLICY_ALLOW_COMMIT_MISMATCH'):flow['invoke']()
    flow['sent'].assert_not_called()
    with pytest.raises(ValueError,match='REASON_REQUIRED'):flow['invoke'](allow_commit_mismatch=True,reason=None)
    flow['invoke'](allow_commit_mismatch=True)
    assert flow['audit'][0]['provenance']=='EXISTING_NON_ANCESTOR'
    assert 'allow_commit_mismatch' in flow['audit'][0]['applied_exceptions']

@pytest.mark.parametrize('kind',['missing','malformed','blob','shallow','wrong_root'])
def test_C07_real_git_non_overridable(repo,kind):
    head=command(repo,'rev-parse','HEAD');root=repo
    if kind=='missing':head='f'*40
    if kind=='malformed':head='--bad'
    if kind=='blob':head=command(repo,'rev-parse','HEAD:file.txt')
    if kind=='shallow':(repo/'.git/shallow').write_text(head+'\n')
    if kind=='wrong_root':root=repo/'results'
    assert provenance.inspect_commit_provenance(head,root)['status']=={
        'missing':'MISSING','malformed':'MALFORMED','blob':'WRONG_OBJECT_TYPE',
        'shallow':'INDETERMINATE','wrong_root':'WRONG_REPOSITORY'}[kind]

def test_C01_decoder_has_no_subprocess_dependency(monkeypatch):
    receipt=complete_receipt(CONTRACT,SIGNER,'0x'+'7'*64,'case','a'*64)
    blocked=Mock(side_effect=AssertionError('Runtime topic subprocess forbidden'))
    monkeypatch.setattr(oc.subprocess,'run',blocked)
    assert oc.extract_evidence_id_from_receipt(receipt,'case','a'*64,CONTRACT,SIGNER,'evidence://case/manifest.json')==1
    blocked.assert_not_called()

@pytest.mark.parametrize('signature,topic',[
    ('EvidenceRegistered(uint256,bytes32,bytes32,address,string)',oc.TOPIC_EVIDENCE_REGISTERED),
    ('CustodyRecorded(uint256,uint8,address,bytes32,bytes32)',oc.TOPIC_CUSTODY_RECORDED)])
def test_C02_ethereum_keccak_independent_cast(signature,topic):
    result=subprocess.run([oc.CAST_BIN,'sig-event',signature],capture_output=True,text=True,timeout=20)
    assert result.returncode==0 and result.stdout.strip()==topic
    assert '0x'+hashlib.sha3_256(signature.encode()).hexdigest()!=topic

@pytest.mark.parametrize('mutation',['emitter','submitter','uri','extra_topic','topic_width','bool_status','zero_id',
    'case','hash','offset','padding','truncated','trailing','duplicate','removed','tx','block','from','to'])
def test_B05_C03_event_mutations_never_verified(flow,mutation):
    r=flow['receipt'];e=r['logs'][0];other='0x'+'1'*40
    if mutation=='emitter':e['address']=other
    if mutation=='submitter':e['data']=registration_data(other,'evidence://test-2a/manifest.json')
    if mutation=='uri':e['data']=registration_data(SIGNER,'evidence://wrong/manifest.json')
    if mutation=='extra_topic':e['topics'].append('0x'+'0'*64)
    if mutation=='topic_width':e['topics'][1]='0x1'
    if mutation=='bool_status':r['status']=True
    if mutation=='zero_id':e['topics'][1]='0x'+'0'*64
    if mutation=='case':e['topics'][2]='0x'+'1'*64
    if mutation=='hash':e['topics'][3]='0x'+'1'*64
    if mutation=='offset':e['data']=e['data'][:66]+f'{32:064x}'+e['data'][130:]
    if mutation=='padding':e['data']=e['data'][:-2]+'01'
    if mutation=='truncated':e['data']=e['data'][:-64]
    if mutation=='trailing':e['data']+='00'*32
    if mutation=='duplicate':r['logs'].append(copy.deepcopy(e))
    if mutation=='removed':e['removed']=True
    if mutation=='tx':e['transactionHash']='0x'+'1'*64
    if mutation=='block':e['blockHash']='0x'+'1'*64
    if mutation=='from':r['from']=other
    if mutation=='to':r['to']=other
    with pytest.raises((ValueError,RuntimeError)):flow['invoke']()
    with sqlite3.connect(flow['db']) as conn:
        assert conn.execute('SELECT COUNT(*) FROM custody_events').fetchone()[0]==0

def test_C08_unknown_send_outcome_no_retry(flow):
    flow['sent'].side_effect=RuntimeError('CAST_TIMEOUT')
    with pytest.raises(RuntimeError,match='CAST_TIMEOUT'):flow['invoke']()
    assert flow['sent'].call_count==1

@pytest.mark.parametrize('flow',[31337,1],indirect=True)
def test_C12_verify_read_only_without_wallet(flow,monkeypatch):
    blocked=Mock(side_effect=AssertionError('Wallet access forbidden'))
    monkeypatch.setattr(oc,'prepare_write',blocked);monkeypatch.setattr(oc,'resolve_signer',blocked)
    result=oc.verify_onchain_evidence(str(flow['pkg']),CONTRACT,anchor_chain_id=31337)
    assert result.exit_code==0 and result.status=='MATCH'
    blocked.assert_not_called();flow['sent'].assert_not_called()

@pytest.mark.parametrize('condition',['dirty','gaps','unfinalized'])
@pytest.mark.parametrize('allowed',[False,True])
def test_B02_each_policy_requires_its_own_flag(flow,condition,allowed):
    result=oc.package_preflight(flow['pkg'])
    state=provenance.inspect_commit_provenance(result.context['export_commit'])
    state['git_state']='CLEAN';result.context['working_tree_dirty']=False
    result.details.update(gaps_count=0,is_finalized=True)
    flag={'dirty':'allow_dirty','gaps':'allow_gaps','unfinalized':'allow_unfinalized'}[condition]
    if condition=='dirty':state['git_state']='DIRTY'
    if condition=='gaps':result.details['gaps_count']=1
    if condition=='unfinalized':result.details['is_finalized']=False
    flags=dict(allow_dirty=False,allow_gaps=False,allow_unfinalized=False,allow_commit_mismatch=False,allow_integrity_failed=False)
    flags[flag]=allowed
    if allowed:
        assert oc.check_anchor_policy(result,state,31337,flags,'controlled-test')['applied_exceptions']==[flag]
    else:
        with pytest.raises(ValueError,match='POLICY_'):oc.check_anchor_policy(result,state,31337,flags,None)

@pytest.mark.parametrize('problem',['rpc','chain','record','context','abi'])
def test_B06_C12_exit_classification(flow,monkeypatch,problem):
    chain=31337
    if problem=='context':chain=None;monkeypatch.delenv('ANCHOR_CHAIN_ID',raising=False)
    if problem=='chain':chain=11155111
    if problem=='rpc':monkeypatch.setattr(oc,'rpc_read',Mock(side_effect=RuntimeError('RPC_QUERY_FAILED')))
    if problem in ('record','abi'):
        def net(url,method,params):
            if method=='eth_call':return '0x'+'0'*64 if problem=='record' else '0x12'
            return flow['network'](url,method,params)
        monkeypatch.setattr(oc,'rpc_read',net)
    result=oc.verify_onchain_evidence(str(flow['pkg']),CONTRACT,anchor_chain_id=chain)
    assert result.exit_code==({'rpc':2,'chain':1,'record':1,'context':2,'abi':2}[problem])
    flow['sent'].assert_not_called()
