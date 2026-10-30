"""Receipt security regressions: actual exporter/verifier, no validation stubs."""
import json
import pytest
from test_integrity_2a import sample, exported, rehash
from forensics.integrity import verify_package, raw_hash
from forensics.integrity import validate_receipt, InvalidPackage
import contextlib
import sqlite3
from forensics.evidence import export_evidence

REQUIRED=['transactionHash','transactionIndex','blockHash','blockNumber','from','gasUsed',
          'cumulativeGasUsed','logs','logsBloom','effectiveGasPrice','status']

def alter(pkg, action):
    path=pkg/'raw_receipts.jsonl'
    rows=[json.loads(line) for line in path.read_text().splitlines()]
    action(rows[0]['raw_json'])
    rows[0]['raw_sha256']=raw_hash(rows[0]['raw_json'])
    path.write_text(''.join(json.dumps(r)+'\n' for r in rows),encoding='utf-8')
    rehash(pkg)

@pytest.mark.parametrize('field',REQUIRED)
def test_missing_required_receipt_rejected(tmp_path,sample,field):
    pkg=exported(tmp_path,sample)
    alter(pkg,lambda r:r.pop(field,None))
    result=verify_package(pkg)
    assert result.status=='INVALID' and result.coverage!='FULL'

@pytest.mark.parametrize('value',[None,True,-1,{},'broken','0x','0x00','1'])
def test_invalid_gas_quantity_rejected(tmp_path,sample,value):
    pkg=exported(tmp_path,sample)
    alter(pkg,lambda r:r.update(gasUsed=value))
    assert verify_package(pkg).status=='INVALID'

@pytest.mark.parametrize('field',['from','to'])
def test_receipt_actor_mismatch_rejected(tmp_path,sample,field):
    pkg=exported(tmp_path,sample)
    alter(pkg,lambda r:r.update({field:'0x'+'9'*40}))
    assert verify_package(pkg).status=='INVALID'

@pytest.mark.parametrize('field',REQUIRED)
def test_export_missing_receipt_fields_rejected(tmp_path,sample,field):
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        tx,text=conn.execute('SELECT tx_hash,raw_json FROM receipts LIMIT 1').fetchone()
        raw=json.loads(text);raw.pop(field)
        conn.execute('UPDATE receipts SET raw_json=?,raw_sha256=? WHERE tx_hash=?',
                     (json.dumps(raw),raw_hash(raw),tx));conn.commit()
    with pytest.raises((ValueError,RuntimeError)):
        export_evidence('missing',0,2,str(tmp_path/'rejected'),str(sample))
    assert not (tmp_path/'rejected').exists()

@pytest.mark.parametrize('value',[0,7])
@pytest.mark.parametrize('success',[False,True])
def test_creation_receipt_policy(sample,value,success):
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        raw=json.loads(conn.execute('SELECT raw_json FROM receipts LIMIT 1').fetchone()[0])
        tx=json.loads(conn.execute('SELECT raw_json FROM transactions LIMIT 1').fetchone()[0])
    tx.update(to=None,value=hex(value))
    raw.update(to=None,status='0x1' if success else '0x0',contractAddress='0x'+'3'*40 if success else None)
    validate_receipt(raw,tx)
    if success:
        raw.pop('contractAddress')
        with pytest.raises(InvalidPackage): validate_receipt(raw,tx)
    else:
        raw['contractAddress']='0x'+'3'*40
        with pytest.raises(InvalidPackage): validate_receipt(raw,tx)

def test_optional_fields_and_unsupported_profiles(sample):
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        raw=json.loads(conn.execute('SELECT raw_json FROM receipts LIMIT 1').fetchone()[0])
        tx=json.loads(conn.execute('SELECT raw_json FROM transactions LIMIT 1').fetchone()[0])
    raw.pop('to');raw.pop('contractAddress')
    validate_receipt(raw,tx)
    for kind in range(5):
        r=dict(raw,type=hex(kind));t=dict(tx,type=hex(kind))
        if kind==3:r.update(blobGasUsed='0x20000',blobGasPrice='0x1')
        validate_receipt(r,t)
    for r in (dict(raw,type='0x5'),dict(raw,root='0x'+'0'*64)):
        with pytest.raises(InvalidPackage):validate_receipt(r,tx)

@pytest.mark.parametrize('table',['blocks','transactions','receipts'])
def test_raw_hash_guard_retained(tmp_path,sample,table):
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        conn.execute('UPDATE '+table+' SET raw_sha256=?',('f'*64,));conn.commit()
    with pytest.raises((ValueError,RuntimeError)):exported(tmp_path,sample)

def test_cli_missing_receipt_is_invalid(tmp_path,sample,capsys):
    from forensics.cli import build_parser, cli_verify_manifest
    pkg=exported(tmp_path,sample)
    alter(pkg,lambda r:r.pop('gasUsed'))
    args=build_parser().parse_args(['verify-manifest',str(pkg)])
    assert cli_verify_manifest(args)==1
    output=capsys.readouterr().out
    assert 'INVALID' in output and 'coverage=LIMITED' in output and 'coverage=FULL' not in output

@pytest.mark.parametrize('kind',range(5))
def test_optional_type_byte_encoding(sample,kind):
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        raw=json.loads(conn.execute('SELECT raw_json FROM receipts LIMIT 1').fetchone()[0])
        tx=json.loads(conn.execute('SELECT raw_json FROM transactions LIMIT 1').fetchone()[0])
    raw['type']=f'0x{kind:02x}';tx['type']=hex(kind)
    if kind==3:raw.update(blobGasUsed='0x20000',blobGasPrice='0x1')
    validate_receipt(raw,tx)

@pytest.mark.parametrize('field,value',[
    ('transactionHash',None),('blockHash','0x12'),('transactionIndex',True),
    ('blockNumber',-1),('from',{}),('cumulativeGasUsed',None),
    ('logs',{}),('logsBloom','0x00'),('effectiveGasPrice','-1'),('status','0x2'),
    ('gasUsed','0x'+'1'*65),('cumulativeGasUsed','0x1')])
def test_invalid_required_shape_rehashed(tmp_path,sample,field,value):
    pkg=exported(tmp_path,sample)
    alter(pkg,lambda r:r.update({field:value}))
    result=verify_package(pkg)
    assert result.status=='INVALID' and result.coverage=='LIMITED'

@pytest.mark.parametrize('field,value',[
    ('gasUsed',None),('gasUsed',True),('gasUsed',-1),('gasUsed','bad'),
    ('from','0x'+'9'*40),('to','0x'+'9'*40)])
def test_export_invalid_receipt_rejected(tmp_path,sample,field,value):
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        tx,text=conn.execute('SELECT tx_hash,raw_json FROM receipts LIMIT 1').fetchone()
        raw=json.loads(text);raw[field]=value
        conn.execute('UPDATE receipts SET raw_json=?,raw_sha256=? WHERE tx_hash=?',
                     (json.dumps(raw),raw_hash(raw),tx));conn.commit()
    with pytest.raises((ValueError,RuntimeError)):exported(tmp_path,sample)
    assert not (tmp_path/'package').exists()
