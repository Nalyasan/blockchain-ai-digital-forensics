"""Phase 2B integration: fresh loopback Anvil, explicit exclusive output, no personal credentials."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from evidence_output import reserve_output

ROOT=Path(__file__).resolve().parents[1]


def run(output):
    report={'status':'FAIL','chain_id':31337,'public_rpc_used':False,
            'personal_credentials_accessed':False,'checks':[],'receipts':[]}
    stage='setup';process=None;old=Path.cwd();saved=dict(os.environ)
    def require(value,code):
        if not value:raise AssertionError(code)
    def passed(name,**values):report['checks'].append(dict(name=name,status='PASS',**values))
    @contextlib.contextmanager
    def workspace():
        with tempfile.TemporaryDirectory(prefix='p3-2b-local-') as temp:
            try:
                yield temp
            finally:
                os.chdir(old)
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
    try:
        with workspace() as temp:
            work=Path(temp);os.chdir(work)
            allowed={'SYSTEMROOT','WINDIR','PATH','PATHEXT','COMSPEC','TEMP','TMP','USERPROFILE','HOMEDRIVE','HOMEPATH'}
            os.environ.clear();os.environ.update({k:v for k,v in saved.items() if k.upper() in allowed})
            os.environ.update(PYTHONUTF8='1',PYTHONDONTWRITEBYTECODE='1',NO_PROXY='*',RPC_SYNTHETIC='true',
                              RPC_LABEL='anvil-2b-local',CONFIRMATIONS='0',RATE_LIMIT_RPS='100',ANCHOR_CHAIN_ID='31337')
            sys.path.insert(0,str(ROOT))
            suffix='.exe' if os.name=='nt' else ''
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            url=f'http://127.0.0.1:{port}';os.environ['RPC_URL']=url
            from forensics import onchain as oc
            from forensics.evidence import export_evidence
            from forensics.integrity import verify_package
            stage='anvil_start'
            process=subprocess.Popen([str(ROOT/'tools/foundry'/('anvil'+suffix)),'--host','127.0.0.1','--port',str(port),'--chain-id','31337'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            deadline=time.monotonic()+20
            while True:
                require(process.poll() is None,'ANVIL_EXITED')
                try:
                    require(oc.get_rpc_chain_id(url)==31337,'CHAIN_INVALID');break
                except RuntimeError:
                    require(time.monotonic()<deadline,'START_TIMEOUT');time.sleep(.1)
            owner=oc.rpc_read(url,'eth_accounts',[])[0]
            stage='deploy_local'
            artifact=json.loads((ROOT/'contracts/out/EvidenceRegistry.sol/EvidenceRegistry.json').read_text())
            raw=oc.run_cast_send(['--from',owner,'--unlocked','--rpc-url',url,'--chain','31337','--json','--create',artifact['bytecode']['object']])
            deployed=json.loads(raw);contract=deployed['contractAddress'];report['receipts'].append(deployed)
            stage='collect_export'
            import collector
            db=work/'source.db';head=int(oc.rpc_read(url,'eth_blockNumber',[]),16)
            with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                with contextlib.closing(collector.db(str(db))) as conn:collector.sync_range(conn,31337,0,head)
            pkg=work/'package';export_evidence('group2b',0,head,str(pkg),str(db))
            require(verify_package(pkg).status=='VALID','PACKAGE_INVALID')
            passed('S1_real_collect_export')
            options=dict(contract_address=contract,db_path=str(db),from_addr=owner,rpc_url=url,allow_dirty=True,reason='controlled-test')
            stage='anchor'
            anchor=oc.anchor_evidence(str(pkg),**options)
            receipt=oc.get_transaction_receipt(anchor['tx_hash'],url);report['receipts'].append(receipt)
            require(receipt['logs'][0]['topics'][0]==oc.TOPIC_EVIDENCE_REGISTERED,'TOPIC_REGISTRATION')
            with contextlib.closing(sqlite3.connect(db)) as conn:
                audits=conn.execute("SELECT metadata FROM audit_events WHERE action='ANCHOR_PREFLIGHT'").fetchall()
                require(len(audits)==1 and json.loads(audits[0][0])['anchor_chain_id']==31337,'AUDIT_MISSING')
            passed('S2_anchor_receipt_event_audit',tx_hash=anchor['tx_hash'],evidence_id=anchor['evidence_id'])
            stage='verify_read_only'
            verified=oc.verify_onchain_evidence(str(pkg),contract,evidence_id=anchor['evidence_id'],rpc_url=url,anchor_chain_id=31337)
            require(verified.exit_code==0,'VERIFY_'+verified.reason_code)
            cli=subprocess.run([sys.executable,'-m','forensics.cli','verify-onchain',str(pkg),'--contract',contract,
                                '--rpc-url',url,'--anchor-chain-id','31337'],env=dict(os.environ,PYTHONPATH=str(ROOT)),
                               capture_output=True,text=True,timeout=40)
            require(cli.returncode==0,'CLI_MATCH_FAILED')
            passed('S3_verify_without_keystore',exit_code=cli.returncode,stdout=cli.stdout,details=verified.details)
            stage='custody'
            custody=oc.record_custody_action(anchor['evidence_id'],1,'0x'+anchor['manifest_sha256'],'group2b',contract,
                                             db_path=str(db),from_addr=owner,rpc_url=url)
            receipt=oc.get_transaction_receipt(custody['tx_hash'],url);report['receipts'].append(receipt)
            require(receipt['logs'][0]['topics'][0]==oc.TOPIC_CUSTODY_RECORDED,'TOPIC_CUSTODY')
            passed('S4_custody_actual_event',tx_hash=custody['tx_hash'])
            for mode in ('tamper','missing_receipt','extra'):
                stage='reject_'+mode
                bad=work/mode;shutil.copytree(pkg,bad)
                if mode=='tamper':(bad/'timeline.csv').write_text('tampered')
                elif mode=='missing_receipt':(bad/'raw_receipts.jsonl').unlink()
                else:(bad/'extra.txt').write_text('extra')
                nonce=oc.rpc_read(url,'eth_getTransactionCount',[owner,'latest'])
                denied=False
                try:oc.anchor_evidence(str(bad),**options)
                except (ValueError,RuntimeError):denied=True
                require(denied and oc.rpc_read(url,'eth_getTransactionCount',[owner,'latest'])==nonce,'REFUSAL_SENT')
                check=oc.verify_onchain_evidence(str(bad),contract,rpc_url=url,anchor_chain_id=31337)
                require(check.exit_code==1,'TAMPER_NOT_MISMATCH')
                passed('S5_'+mode+'_no_send',exit_code=check.exit_code)
            stage='rpc_error'
            with socket.socket() as closed:
                closed.bind(('127.0.0.1',0));dead=f'http://127.0.0.1:{closed.getsockname()[1]}'
                failure=oc.verify_onchain_evidence(str(pkg),contract,rpc_url=dead,anchor_chain_id=31337)
            require(failure.exit_code==2,'RPC_NOT_ERROR');passed('S6_rpc_error',exit_code=2)
            stage='declaration_exception'
            diag=work/'diagnostic';shutil.copytree(pkg,diag)
            manifest=diag/'manifest.json';data=json.loads(manifest.read_text())
            data['integrity_checks']['verify_local'].update(status='FAILED',mismatches=1)
            manifest.write_text(json.dumps(data),encoding='utf-8')
            prior=manifest.read_bytes()
            result=oc.anchor_evidence(str(diag),allow_integrity_failed=True,**options)
            require(result['status']=='ANCHORED_WITH_EXCEPTION' and manifest.read_bytes()==prior,'DECLARATION_CHANGED')
            require(verify_package(diag).status=='INVALID','DECLARATION_UPGRADED')
            checked=oc.verify_onchain_evidence(str(diag),contract,rpc_url=url,anchor_chain_id=31337)
            require(checked.exit_code==1,'DIAGNOSTIC_FALSE_MATCH')
            report['receipts'].append(oc.get_transaction_receipt(result['tx_hash'],url))
            passed('S7_diagnostic_preserves_FAILED',tx_hash=result['tx_hash'],exit_code=checked.exit_code)
            shutil.copytree(pkg,output/'package');shutil.copytree(diag,output/'diagnostic')
            with contextlib.closing(sqlite3.connect(db)) as conn:
                report['audit_preflight']=[json.loads(x[0]) for x in conn.execute("SELECT metadata FROM audit_events WHERE action='ANCHOR_PREFLIGHT'")]
            report['status']='PASS'
    except Exception as exc:
        code=str(exc)
        import re
        report['failure']={'stage':stage,'type':type(exc).__name__,
                           'code':code if re.fullmatch('[A-Z_]+',code) else 'STAGE_FAILED'}
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
        os.chdir(old);os.environ.clear();os.environ.update(saved)
    (output/'smoke.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output-dir',required=True)
    parser.add_argument('--protected-root',required=True,action='append');args=parser.parse_args()
    out=reserve_output(args.output_dir,[ROOT,*args.protected_root])
    result=run(out);print(json.dumps(result,indent=2));sys.exit(0 if result['status']=='PASS' else 1)
