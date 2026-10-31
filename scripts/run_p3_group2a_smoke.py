"""Real Collector/export smoke on a fresh, unforked loopback Anvil only.

Run via run_p3_group1b_checks.py to compile the exact source snapshot first.
No wallets, .env files or public RPC endpoints are used by this harness.
"""
import contextlib
import csv
import hashlib
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
import uuid

ROOT = Path(__file__).resolve().parents[1]
HIDDEN = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


def require(condition, code):
    if not condition:
        raise AssertionError(code)


def run_smoke():
    evidence = os.environ.get('P3_2A_EVIDENCE_DIR')
    report = {'status': 'FAIL', 'chain_id': 31337, 'public_rpc_used': False,
              'personal_credentials_accessed': False, 'checks': [], 'transactions': []}
    stage, process, work = 'setup', None, None
    old_cwd = Path.cwd()
    saved_env = dict(os.environ)
    captured = io.StringIO()
    artifact_dir = None
    if evidence:
        artifact_dir = Path(evidence) / ('anvil-2a-' + uuid.uuid4().hex)
        artifact_dir.mkdir(parents=True, exist_ok=False)
    def passed(name, **values):
        report['checks'].append(dict(name=name, status='PASS', **values))
    try:
        with tempfile.TemporaryDirectory(prefix='p3-2a-smoke-') as folder:
            work = Path(folder)
            os.chdir(work)  # Collector dotenv lookup sees only this empty directory.
            allowed = {'SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC', 'TEMP', 'TMP',
                       'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH'}
            os.environ.clear()
            os.environ.update({k:v for k,v in saved_env.items() if k.upper() in allowed})
            os.environ.update(PYTHONUTF8='1', NO_PROXY='*', RPC_SYNTHETIC='true',
                              RPC_LABEL='anvil-group2a-local', CONFIRMATIONS='0', RATE_LIMIT_RPS='100')
            sys.path.insert(0, str(ROOT))
            with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                try:
                    stage = 'start_local_anvil'
                    suffix = '.exe' if os.name == 'nt' else ''
                    anvil, cast = [ROOT/'tools/foundry'/(name+suffix) for name in ('anvil', 'cast')]
                    with socket.socket() as sock:
                        sock.bind(('127.0.0.1', 0))
                        port = sock.getsockname()[1]
                    url = f'http://127.0.0.1:{port}'
                    os.environ['RPC_URL'] = url
                    # Neither startup output nor cast stderr is ever published.
                    process = subprocess.Popen([str(anvil), '--host', '127.0.0.1', '--port', str(port),
                        '--chain-id', '31337'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        creationflags=HIDDEN)
                    from forensics.onchain import rpc_read
                    deadline = time.monotonic() + 20
                    while True:
                        require(process.poll() is None, 'ANVIL_EXITED')
                        try:
                            require(int(rpc_read(url, 'eth_chainId', []), 16) == 31337, 'CHAIN_MISMATCH')
                            break
                        except RuntimeError:
                            require(time.monotonic() < deadline, 'ANVIL_START_TIMEOUT')
                            time.sleep(0.1)
                    require('anvil' in rpc_read(url, 'web3_clientVersion', []).lower(), 'NOT_ANVIL')
                    owner, recipient = rpc_read(url, 'eth_accounts', [])[:2]
                    def send(arguments):
                        result = subprocess.run([str(cast), 'send', '--from', owner, '--unlocked',
                            '--rpc-url', url, '--chain', '31337', '--json', *arguments],
                            cwd=work, capture_output=True, timeout=40, creationflags=HIDDEN)
                        require(result.returncode == 0, 'CAST_SEND_FAILED')
                        receipt = json.loads(result.stdout)
                        require(int(receipt['status'], 16) == 1, 'RECEIPT_FAILED')
                        report['transactions'].append(receipt)
                        return receipt
                    stage = 'eth_erc20_transactions'
                    eth = send([recipient, '--value', '1000000000000000000'])
                    artifact = json.loads((ROOT/'contracts/out/MockToken.sol/MockERC20.json').read_text(encoding='utf-8'))
                    deployed = send(['--create', artifact['bytecode']['object'] + format(10**24, '064x')])
                    token = deployed['contractAddress']
                    token_tx = send([token, 'transfer(address,uint256)', recipient, '12345'])
                    # A value-bearing contract creation and a reverted tx exercise
                    # parser behavior without changing the Solidity project.
                    created = send(['--value', '7', '--create', '0x60006000f3'])
                    fail_data = subprocess.run([str(cast), 'calldata', 'transfer(address,uint256)', recipient,
                        str(10**30)], capture_output=True, timeout=20, creationflags=HIDDEN)
                    require(fail_data.returncode == 0, 'ENCODE_FAILED')
                    reverted_hash = rpc_read(url, 'eth_sendTransaction', [{
                        'from': owner, 'to': token, 'data': fail_data.stdout.decode().strip(), 'gas': '0x493e0'}])
                    deadline = time.monotonic() + 10.0
                    reverted = None
                    while time.monotonic() < deadline:
                        reverted = rpc_read(url, 'eth_getTransactionReceipt', [reverted_hash])
                        if reverted is not None:
                            break
                        time.sleep(0.05)
                    require(reverted is not None and int(reverted['status'],16) == 0, 'EXPECTED_REVERT')
                    report['transactions'].append(reverted)
                    head = int(rpc_read(url, 'eth_blockNumber', []),16)
                    stage = 'collector_snapshot_export'
                    import collector
                    from forensics.evidence import export_evidence
                    from forensics.integrity import verify_package
                    db_file = work/'collected.db'
                    with contextlib.closing(collector.db(str(db_file))) as conn:
                        collector.sync_range(conn, 31337, 0, head)
                    pkg = work/'package'
                    manifest = export_evidence('anvil-group2a', 0, head, str(pkg), str(db_file), operator='local-smoke')
                    verified = verify_package(pkg, db_file)
                    require(verified.status == 'VALID' and verified.coverage == 'FULL', 'FULL_VERIFY_FAILED')
                    with (pkg/'asset_transfers.csv').open(newline='', encoding='utf-8') as f:
                        transfers = list(csv.DictReader(f))
                    require(any(t['tx_hash'] == eth['transactionHash'] and t['asset_id']=='NATIVE' for t in transfers), 'ETH_MISSING')
                    require(any(t['tx_hash']==token_tx['transactionHash'] and t['asset_id']==token.lower()
                                and t['amount_raw']=='12345' for t in transfers), 'ERC20_MISSING')
                    require(any(t['tx_hash']==created['transactionHash'] and t['to_addr']==created['contractAddress'].lower()
                                and t['amount_raw']=='7' for t in transfers), 'CREATION_TRANSFER_MISSING')
                    require(not any(t['tx_hash']==reverted_hash for t in transfers), 'REVERT_TRANSFER_PRESENT')
                    cli_env = dict(os.environ, PYTHONPATH=str(ROOT))
                    cli = subprocess.run([sys.executable, '-m', 'forensics.cli', 'verify-manifest', str(pkg),
                        '--db', str(db_file)], cwd=work, env=cli_env, capture_output=True, timeout=30, encoding='utf-8')
                    require(cli.returncode == 0 and 'coverage=FULL' in cli.stdout, 'CLI_FULL_FAILED')
                    passed('S1_collect_export_verify_full', exit_code=cli.returncode, cli_stdout=cli.stdout,
                           manifest_sha256=verified.manifest_sha256, package_digest=manifest['package_digest'],
                           counts=manifest['counts'], eth_erc20_creation_revert=True)
                    if artifact_dir:
                        shutil.copytree(pkg, artifact_dir/'package')
                        shutil.copy2(db_file, artifact_dir/'collected.db')
                    stage = 'tamper_detection'
                    for mode in ('tampered', 'missing_receipts', 'extra'):
                        altered = work/mode
                        shutil.copytree(pkg, altered)
                        if mode == 'tampered': (altered/'timeline.csv').write_bytes(b'tampered\n')
                        elif mode == 'missing_receipts': (altered/'raw_receipts.jsonl').unlink()
                        else: (altered/'extra.txt').write_text('extra')
                        result = verify_package(altered)
                        require(result.status == 'INVALID', 'TAMPER_ACCEPTED')
                        passed('S2_'+mode, reason_code=result.reason_code.value)
                    stage = 'corrupt_database'
                    corrupt = work/'corrupt.db'
                    shutil.copy2(db_file, corrupt)
                    with contextlib.closing(sqlite3.connect(corrupt)) as conn:
                        before = conn.execute('SELECT COUNT(*) FROM evidence_exports').fetchone()[0]
                        conn.execute("UPDATE receipts SET raw_sha256='corrupted'")
                        conn.commit()
                    rejected = False
                    try:
                        export_evidence('corrupted', 0, head, str(work/'rejected'), str(corrupt))
                    except (ValueError, RuntimeError):
                        rejected = True
                    require(rejected and not (work/'rejected').exists(), 'CORRUPT_EXPORT_ACCEPTED')
                    with contextlib.closing(sqlite3.connect(corrupt)) as conn:
                        require(conn.execute('SELECT COUNT(*) FROM evidence_exports').fetchone()[0] == before, 'FALSE_SUCCESS_ROW')
                    passed('S3_corrupt_receipt_export_rejected', success_rows_added=0)
                    stage = 'filtered_collection'
                    filtered = work/'filtered.db'
                    with contextlib.closing(collector.db(str(filtered))) as conn:
                        collector.sync_range(conn, 31337, 0, head, watch_addresses=['0x'+'9'*40])
                    rejected = False
                    try:
                        export_evidence('filtered', 0, head, str(work/'filtered-package'), str(filtered))
                    except (ValueError, RuntimeError):
                        rejected = True
                    require(rejected and not (work/'filtered-package').exists(), 'FILTERED_EXPORT_ACCEPTED')
                    passed('T5_real_watch_filter_rejected')
                finally:
                    if process is not None:
                        process.terminate()
                        try: process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=10)
                    os.chdir(old_cwd)
        require(work is not None and not work.exists() and process.poll() is not None, 'CLEANUP_FAILED')
        passed('S5_anvil_and_temporary_resources_removed')
        report['status'] = 'PASS'
    except Exception as exc:
        # Fixed stage/type only: no subprocess output, argv, path or exception text.
        report['failure'] = {'stage': stage, 'type': type(exc).__name__}
    finally:
        os.chdir(old_cwd)
        os.environ.clear()
        os.environ.update(saved_env)
    if artifact_dir:
        (artifact_dir/'smoke.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        report['artifact_directory'] = artifact_dir.name
    return report


if __name__ == '__main__':
    result = run_smoke()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result['status'] == 'PASS' else 1)
