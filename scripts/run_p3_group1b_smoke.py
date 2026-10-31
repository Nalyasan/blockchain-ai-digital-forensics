"""Real, local-only P3 guard integration. Never loads the project's .env.

Requires Anvil/cast and a compiled EvidenceRegistry artifact (forge build --root
contracts). Passwords, DBs and packages live in a private temporary directory.
A uniquely reserved encrypted wallet in Foundry's default keystore directory is
removed on exit. Output never includes child-process diagnostics.
Run in a fresh Python process; this script deliberately isolates its environment.
"""
import contextlib
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
HIDDEN = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
KEYSTORE_ROOT = Path.home() / '.foundry/keystores'


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def local_url(url):
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    require(parsed.scheme == 'http' and parsed.hostname == '127.0.0.1', 'NONLOCAL_RPC')


def clean_environment(home):
    allowed = {'SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC', 'TEMP', 'TMP'}
    env = {k: v for k, v in os.environ.items() if k.upper() in allowed}
    env.update(HOME=str(home), USERPROFILE=str(home), FOUNDRY_DIR=str(home / '.foundry'),
               PYTHONUTF8='1', PYTHONIOENCODING='utf-8', NO_PROXY='*')
    return env


def private_directory(path):
    if os.name == 'nt':
        identity = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'],
                                  capture_output=True, text=True, check=False)
        import re
        match = re.search(r'S-1-5-[0-9-]+', identity.stdout)
        require(identity.returncode == 0 and match, 'ACL_IDENTITY_FAILED')
        rights = ':(OI)(CI)F' if path.is_dir() else ':F'
        result = subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r',
                                 '*' + match.group() + rights,
                                 '*S-1-5-18' + rights], capture_output=True, check=False)
        require(result.returncode == 0, 'ACL_FAILED')
    else:
        path.chmod(0o700 if path.is_dir() else 0o600)


@contextlib.contextmanager
def temporary_keystore():
    # Windows dirs::home_dir uses the OS profile, not an overridden USERPROFILE.
    KEYSTORE_ROOT.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='p3_group1b_', dir=KEYSTORE_ROOT)
    os.close(fd)
    path = Path(name)
    try:
        private_directory(path)
        yield path
    finally:
        path.unlink(missing_ok=True)  # Only the exclusively reserved file.


class ReadProxy:
    """Local fault-injection server. No signing/sending method can be forwarded."""
    READS = {'eth_chainId', 'web3_clientVersion', 'eth_getCode', 'eth_call',
             'eth_getTransactionCount', 'eth_getBalance', 'eth_blockNumber'}

    def __init__(self, upstream, chain=None, client=None, error=None):
        local_url(upstream)
        self.methods = []
        self.writes = 0
        self.upstream, self.chain, self.client, self.error = upstream, chain, client, error
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                try:
                    request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    method = request['method']
                    proxy.methods.append(method)
                    response = {'jsonrpc': '2.0', 'id': request.get('id')}
                    if method not in proxy.READS:
                        proxy.writes += 1
                        response['error'] = {'code': -32601, 'message': 'read-only test proxy'}
                    elif proxy.error:
                        response['error'] = {'code': -32000, 'message': proxy.error}
                    elif method == 'eth_chainId' and proxy.chain is not None:
                        response['result'] = hex(proxy.chain)
                    elif method == 'web3_clientVersion' and proxy.client:
                        response['result'] = proxy.client
                    else:
                        req = urllib.request.Request(proxy.upstream, data=json.dumps(request).encode(),
                                                     headers={'Content-Type': 'application/json'})
                        with urllib.request.urlopen(req, timeout=5) as upstream_response:
                            response = json.load(upstream_response)
                    payload = json.dumps(response).encode()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except Exception:
                    self.send_error(500, 'test proxy failed')

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def run_smoke():
    report = {'phase': 'P3-1b', 'status': 'FAIL', 'checks': [], 'transactions': []}
    stage = 'setup'
    captured = io.StringIO()
    # No environment files (even hashes of .env) are opened here.
    sample_db = ROOT / 'results/p1/anvil_forensics.db'
    sample_package = ROOT / 'results/p2/case-anvil-p1-001'
    originals = [sample_db] + sorted(sample_package.glob('*'))
    require(sample_db.is_file() and (sample_package / 'manifest.json').is_file(), 'SAMPLES_MISSING')
    before = {str(p.relative_to(ROOT)): digest(p) for p in originals if p.is_file()}
    binaries = {name: ROOT / 'tools/foundry' / (name + ('.exe' if os.name == 'nt' else ''))
                for name in ('cast', 'anvil')}
    require(all(p.is_file() for p in binaries.values()), 'FOUNDRY_MISSING')
    # Fresh subprocess only: importing collector before this point would read .env.
    require('collector' not in sys.modules, 'FRESH_PROCESS_REQUIRED')
    previous_cwd = Path.cwd()
    anvil = None
    with tempfile.TemporaryDirectory(prefix='p3-group1b-') as work, temporary_keystore() as keyfile:
        work = Path(work)
        private_directory(work)
        os.environ.clear()
        os.environ.update(clean_environment_saved(work))
        os.chdir(work)
        sys.path.insert(0, str(ROOT))
        # Fail closed for Python network calls, including accidental redirects.
        def only_loopback(event, args):
            if event == 'socket.connect':
                require(args[1][0] in ('127.0.0.1', '::1'), 'NETWORK_ISOLATION_FAILED')
        sys.addaudithook(only_loopback)
        from forensics import onchain as oc
        oc.CAST_BIN = str(binaries['cast'])
        handler = logging.StreamHandler(captured)
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)
        original_cast = oc._run_cast
        operations = []
        sensitive = []

        def observe_cast(args, timeout=30):
            # Observe and forward to the REAL binary; no return value is mocked.
            if '--rpc-url' in args:
                local_url(args[args.index('--rpc-url') + 1])
            require('--private-key' not in args and '--password' not in args, 'SECRET_ARG')
            if args[0] == 'send':
                require(args[args.index('--chain') + 1] == '31337', 'SEND_CHAIN_NOT_LOCAL')
            operations.append(args[0])
            return original_cast(args, timeout)
        oc._run_cast = observe_cast

        def raw_cast(args, extra_env=None):
            if '--rpc-url' in args:
                local_url(args[args.index('--rpc-url') + 1])
            result = subprocess.run([str(binaries['cast'])] + args,
                                    env=dict(os.environ, **(extra_env or {})),
                                    capture_output=True, text=True, encoding='utf-8',
                                    errors='replace', timeout=45, creationflags=HIDDEN)
            if result.returncode:
                report['tool_exit_code'] = result.returncode
                report['tool_error_signals'] = [s for s in ('password', 'No such file', 'cannot find',
                    'unexpected argument', 'keystore', 'Access is denied', 'terminal', 'not exist',
                    'decrypt', 'MAC', 'system cannot', 'Ethereum', 'directory', 'os error 2') if s in result.stderr]
            require(result.returncode == 0, 'REAL_CAST_FAILED')
            return result.stdout.strip()

        def passed(name, **evidence):
            report['checks'].append({'name': name, 'status': 'PASS', **evidence})

        try:
            with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                stage = 'anvil_start'
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0))
                    port = sock.getsockname()[1]
                url = f'http://127.0.0.1:{port}'
                anvil = subprocess.Popen([str(binaries['anvil']), '--host', '127.0.0.1',
                                          '--port', str(port), '--chain-id', '31337'],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         creationflags=HIDDEN)
                deadline = time.monotonic() + 20
                while True:
                    require(anvil.poll() is None, 'ANVIL_EXITED')
                    try:
                        require(oc.get_rpc_chain_id(url) == 31337, 'WRONG_LOCAL_CHAIN')
                        break
                    except RuntimeError:
                        require(time.monotonic() < deadline, 'ANVIL_START_TIMEOUT')
                        time.sleep(0.1)
                os.environ['ANCHOR_CHAIN_ID'] = '31337'
                owner = oc.rpc_read(url, 'eth_accounts', [])[0].lower()
                report['chain_id'] = 31337
                report['client'] = oc.rpc_read(url, 'web3_clientVersion', [])
                report['cast_version'] = raw_cast(['--version']).splitlines()[0]
                stage = 'encrypted_keystore'
                keydir = keyfile.parent
                account = keyfile.name
                password = secrets.token_urlsafe(32)
                sensitive.append(password)
                password_file = work / 'password.txt'
                password_file.write_text(password, encoding='utf-8')
                created = raw_cast(['wallet', 'new', str(keydir), account, '--force'], {'CAST_PASSWORD': password})
                private_directory(keyfile)
                stage = 'resolve_encrypted_keystore'
                wallet = json.loads(keyfile.read_text())
                require('crypto' in wallet or 'Crypto' in wallet, 'KEYSTORE_NOT_ENCRYPTED')
                signer = oc.resolve_signer(account, str(password_file))
                import re
                created_address = re.search(r'0x[0-9a-fA-F]{40}\b', created)
                require(created_address and signer == oc.normalize_address(created_address.group()),
                        'KEYSTORE_ADDRESS_MISMATCH')
                passed('real_keystore_address', address=signer)
                oc.rpc_read(url, 'anvil_setBalance', [signer, hex(10**20)])
                stage = 'local_deploy'
                artifact = json.loads((ROOT / 'contracts/out/EvidenceRegistry.sol/EvidenceRegistry.json').read_text(encoding='utf-8'))
                bytecode = artifact['bytecode']['object']
                deployed = json.loads(raw_cast(['send', '--from', owner, '--unlocked', '--rpc-url', url,
                                               '--chain', '31337', '--json', '--create', bytecode]))
                contract = deployed['contractAddress']
                require(int(deployed['status'], 16) == 1, 'DEPLOY_FAILED')
                report['contract'] = contract
                report['transactions'].append({'kind': 'deploy', 'hash': deployed['transactionHash'], 'from': owner})
                raw_cast(['send', contract, 'setInvestigator(address,bool)', signer, 'true',
                          '--from', owner, '--unlocked', '--rpc-url', url, '--chain', '31337', '--json'])
                db = work / 'sample.db'
                shutil.copy2(sample_db, db)
                from forensics.schemas import migrate_group3
                with contextlib.closing(sqlite3.connect(db)) as m_conn:
                    migrate_group3(m_conn)
                package = work / 'package'
                from forensics.evidence import export_evidence
                with contextlib.closing(sqlite3.connect(db)) as sample_conn:
                    lo, hi = sample_conn.execute("SELECT MIN(number),MAX(number) FROM blocks WHERE status='canonical'").fetchone()
                export_evidence('group1b', lo, hi, str(package), str(db), allow_gaps=True)
                manifest = package / 'manifest.json'

                def invoke(kind, **changes):
                    opts = dict(contract_address=contract, db_path=str(db), account=account,
                                password_file=str(password_file), rpc_url=url)
                    opts.update(changes)
                    if kind == 'anchor':
                        return oc.anchor_evidence(str(manifest), allow_dirty=True, allow_unfinalized=True,
                                                  allow_gaps=True, reason='controlled-test', **opts)
                    return oc.record_custody_action(1, 1, '0x' + digest(manifest), 'group1b', **opts)

                def call(signature, *args):
                    return raw_cast(['call', contract, signature, *map(str, args), '--rpc-url', url])

                def state():
                    with contextlib.closing(sqlite3.connect(db)) as conn:
                        database = '\n'.join(conn.iterdump())
                    return (oc.rpc_read(url, 'eth_getTransactionCount', [signer, 'pending']),
                            oc.rpc_read(url, 'eth_getTransactionCount', [owner, 'pending']),
                            oc.rpc_read(url, 'eth_blockNumber', []),
                            call('nextEvidenceId()(uint256)'),
                            hashlib.sha256(database.encode()).hexdigest())

                def reject(name, action, fragment):
                    nonlocal stage
                    stage = name
                    prior = state()
                    sends = operations.count('send')
                    try:
                        action()
                    except (ValueError, RuntimeError) as exc:
                        require(fragment in str(exc), 'UNEXPECTED_REJECTION')
                        captured.write(str(exc))
                    else:
                        raise RuntimeError('GUARD_ACCEPTED_INVALID_INPUT')
                    require(operations.count('send') == sends, 'REJECTED_CALL_SENT')
                    require(state() == prior, 'REJECTED_CALL_CHANGED_STATE')
                    passed(name, cast_send_calls=0, nonce_chain_db_unchanged=True)

                for kind in ('anchor', 'custody'):
                    reject(kind + '_from_mismatch', lambda: invoke(kind, from_addr=owner), 'SIGNER_MISMATCH')
                    os.environ['ANCHOR_FROM'] = owner
                    reject(kind + '_env_from_mismatch', lambda: invoke(kind), 'SIGNER_MISMATCH')
                    del os.environ['ANCHOR_FROM']
                    reject(kind + '_no_bytecode', lambda: invoke(kind, contract_address=owner), 'CONTRACT_CODE_MISSING')
                    os.environ['ANCHOR_CHAIN_ID'] = '11155111'
                    reject(kind + '_live_chain_mismatch', lambda: invoke(kind), 'Chain ID mismatch')
                    os.environ['ANCHOR_CHAIN_ID'] = '31337'
                    with ReadProxy(url, client='Geth/test-local-only') as proxy:
                        reject(kind + '_non_anvil_client', lambda: invoke(kind, account=None,
                               from_addr=owner, rpc_url=proxy.url), 'ANVIL_CLIENT_REQUIRED')
                        require(proxy.writes == 0, 'PROXY_WRITE_ATTEMPT')
                    wrong_password = work / 'wrong-password.txt'
                    wrong_password.write_text(secrets.token_urlsafe(32), encoding='utf-8')
                    sensitive.append(wrong_password.read_text())
                    reject(kind + '_wrong_password', lambda: invoke(kind, password_file=str(wrong_password)), 'CAST_EXIT_')
                    reject(kind + '_missing_keystore', lambda: invoke(kind, account=account + '_missing'), 'CAST_EXIT_')
                    # An HTTP endpoint outside loopback must be rejected before any connection.
                    reject(kind + '_nonlocal_http', lambda: invoke(kind, account=None,
                           from_addr=owner, rpc_url='http://192.0.2.1:8545'), 'RPC_TLS_REQUIRED')
                    # Route reads to real local Anvil, while exercising URL policy on a
                    # nonloopback HTTPS URL. This is transport injection, not public RPC.
                    real_read = oc.rpc_read
                    remote = 'https://group1b.invalid'
                    def route_read(endpoint, method, params):
                        return real_read(url if endpoint == remote else endpoint, method, params)
                    oc.rpc_read = route_read
                    try:
                        reject(kind + '_nonlocal_https_local_transport', lambda: invoke(kind,
                               account=None, from_addr=owner, rpc_url=remote), 'loopback')
                    finally:
                        oc.rpc_read = real_read
                    with socket.socket() as unavailable:
                        unavailable.bind(('127.0.0.1', 0))
                        token = secrets.token_urlsafe(24)
                        sensitive.append(token)
                        unavailable_url = f'http://127.0.0.1:{unavailable.getsockname()[1]}/{token}'
                        reject(kind + '_rpc_unavailable', lambda: invoke(kind, rpc_url=unavailable_url),
                               'RPC_QUERY_FAILED')

                    stage = kind + '_cli_from_mismatch'
                    prior = state()
                    cli_args = (['anchor', str(manifest), '--allow-dirty', '--allow-unfinalized', '--allow-gaps',
                                 '--reason', 'controlled-test'] if kind == 'anchor' else
                                ['custody', '--evidence-id', '1', '--action', '1',
                                 '--artifact-hash', '0x' + digest(manifest), '--note', 'group1b'])
                    cli_args += ['--contract', contract, '--db', str(db), '--account', account,
                                 '--password-file', str(password_file), '--from', owner, '--rpc-url', url]
                    cli = subprocess.run([sys.executable, '-m', 'forensics.cli'] + cli_args,
                                         env=dict(os.environ, PYTHONPATH=str(ROOT)), capture_output=True,
                                         encoding='utf-8', errors='replace', timeout=30)
                    captured.write(cli.stdout + cli.stderr)
                    require(cli.returncode == 1 and 'SIGNER_MISMATCH' in cli.stderr, 'CLI_GUARD_FAILED')
                    require(state() == prior, 'CLI_CHANGED_STATE')
                    passed(stage, exit_code=1, nonce_chain_db_unchanged=True)

                stage = 'default_accounts'
                defaults = oc.compute_anvil_default_accounts()
                require(defaults == [a.lower() for a in oc.rpc_read(url, 'eth_accounts', [])], 'DEFAULT_DERIVATION_MISMATCH')
                passed('ten_defaults_match_real_anvil')
                for chain in (11155111, 1):
                    os.environ.pop('ANCHOR_CHAIN_ID', None)
                    with ReadProxy(url, chain=chain) as proxy:
                        for i, address in enumerate(defaults):
                            for kind in ('anchor', 'custody'):
                                fragment = 'Chặn khóa mặc định Anvil' if chain == 11155111 else 'không nằm trong danh sách'
                                reject(f'{kind}_default_{i}_simulated_chain_{chain}',
                                       lambda: invoke(kind, account=None, from_addr=address,
                                                      rpc_url=proxy.url), fragment)
                        if chain == 11155111:
                            for kind in ('anchor', 'custody'):
                                reject(kind + '_nonlocal_chain_requires_keystore', lambda: invoke(kind,
                                       account=None, from_addr=signer, rpc_url=proxy.url), 'bắt buộc sử dụng keystore')
                        require(proxy.writes == 0 and 'eth_chainId' in proxy.methods, 'PROXY_CHECK_FAILED')
                os.environ['ANCHOR_CHAIN_ID'] = '31337'

                stage = 'keystore_anchor'
                result = invoke('anchor', from_addr=signer.upper().replace('0X', '0x'))
                require(result['evidence_id'] == 1 and result['chain_id'] == 31337, 'ANCHOR_RESULT_FAILED')
                for kind, result in [('anchor', result), ('custody', invoke('custody'))]:
                    receipt = oc.get_transaction_receipt(result['tx_hash'], url)
                    transaction = oc.rpc_read(url, 'eth_getTransactionByHash', [result['tx_hash']])
                    require(receipt['from'].lower() == signer and transaction['from'].lower() == signer,
                            'ACTUAL_SIGNER_MISMATCH')
                    require(int(transaction['chainId'], 16) == 31337, 'SIGNED_CHAIN_MISMATCH')
                    with contextlib.closing(sqlite3.connect(db)) as conn:
                        actor = conn.execute('SELECT actor_address FROM custody_events WHERE tx_hash=?',
                                             (result['tx_hash'].lower(),)).fetchone()
                    require(actor and actor[0] == signer, 'DB_SIGNER_MISMATCH')
                    report['transactions'].append({'kind': kind, 'hash': result['tx_hash'], 'from': signer})
                    passed('real_keystore_' + kind + '_receipt_db_chain')
                verified = call('verifyEvidence(uint256,bytes32)(bool,address,uint256)', 1, '0x' + digest(manifest))
                require('true' in verified and signer in verified.lower(), 'REGISTERED_BY_MISMATCH')
                history = call('getCustodyHistory(uint256)((uint256,uint8,address,bytes32,bytes32,uint256)[])', 1)
                require(signer in history.lower(), 'ONCHAIN_CUSTODY_ACTOR_MISMATCH')
                passed('contract_registered_by_and_custody_actor')

                stage = 'unlocked_writes'
                content = json.loads(manifest.read_text(encoding='utf-8'))
                content['case_id'] = 'group1b-unlocked'
                manifest.write_text(json.dumps(content), encoding='utf-8')
                unlocked = invoke('anchor', account=None, from_addr=owner)
                custody = oc.record_custody_action(unlocked['evidence_id'], 2, '0x' + digest(manifest),
                                                  'local-only', contract, str(db), from_addr=owner, rpc_url=url)
                for kind, result in [('unlocked_anchor', unlocked), ('unlocked_custody', custody)]:
                    receipt = oc.get_transaction_receipt(result['tx_hash'], url)
                    require(receipt['from'].lower() == owner and int(receipt['status'], 16) == 1, 'UNLOCKED_FAILED')
                    report['transactions'].append({'kind': kind, 'hash': result['tx_hash'], 'from': owner})
                    passed(kind)

                stage = 'real_cast_redaction'
                # Synthetic canaries only, generated at runtime; never written to output or Git.
                words = ('abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
                         'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid')
                canaries = [secrets.token_hex(32), '0x' + secrets.token_hex(32), secrets.token_urlsafe(24),
                            ' '.join(secrets.choice(words) for _ in range(12)), secrets.token_urlsafe(24)]
                sensitive.extend(canaries)
                with ReadProxy(url, error=' '.join(canaries)) as proxy:
                    secret_url = proxy.url + '/' + canaries[2]
                    args = ['call', contract, 'owner()(address)', '--rpc-url', secret_url]
                    actual = subprocess.run([oc.CAST_BIN] + args, capture_output=True, text=True,
                                            encoding='utf-8', errors='replace', timeout=30)
                    require(actual.returncode != 0 and all(s in actual.stderr for s in canaries),
                            'CAST_ERROR_CANARIES_NOT_EXERCISED')
                    for action in (lambda: oc._run_cast(args),
                                   lambda: oc.rpc_read(secret_url, 'eth_chainId', [])):
                        try:
                            action()
                        except RuntimeError as exc:
                            captured.write(str(exc))
                        else:
                            raise RuntimeError('ERROR_NOT_REJECTED')
                    require(proxy.writes == 0, 'REDACTION_PROXY_WRITE')
                with contextlib.closing(sqlite3.connect(db)) as conn:
                    audit = '\n'.join(conn.iterdump())
                visible = captured.getvalue() + audit + json.dumps(report)
                require(all(s not in visible for s in sensitive), 'SECRET_LEAK_DETECTED')
                passed('real_cast_rpc_stderr_log_audit_redaction', canary_classes=5)
                report['cast_operations'] = {k: operations.count(k) for k in set(operations)}
        except Exception as exc:
            # Never print repr/traceback: exceptions can contain tool args and secrets.
            report['failure_stage'] = stage
            report['failure_type'] = type(exc).__name__
            import re
            code = str(exc).split(':', 1)[0]
            if re.fullmatch(r'[A-Z][A-Z_0-9]{2,60}', code):
                report['failure_code'] = code
        finally:
            oc._run_cast = original_cast
            logging.getLogger().removeHandler(handler)
            logging.shutdown()
            import gc
            gc.collect()
            if anvil:
                anvil.terminate()
                try:
                    anvil.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    anvil.kill()
                    anvil.wait(timeout=5)
            os.chdir(previous_cwd)
    after = {str(p.relative_to(ROOT)): digest(p) for p in originals if p.is_file()}
    require(before == after, 'ORIGINAL_SAMPLE_CHANGED')
    report['original_sample_sha256'] = before
    report['original_samples_unchanged'] = True
    report['temporary_keystore_removed'] = not keyfile.exists()
    report['public_rpc_used'] = False
    if 'failure_stage' not in report:
        report['status'] = 'PASS'
    return report


# Save only an allowlisted process environment before clearing the inherited one.
_BASE_ENV = clean_environment(Path(tempfile.gettempdir()))


def clean_environment_saved(home):
    env = dict(_BASE_ENV)
    env.update(HOME=str(home), USERPROFILE=str(home), FOUNDRY_DIR=str(home / '.foundry'))
    return env


if __name__ == '__main__':
    try:
        output = run_smoke()
    except Exception as error:
        output = {'phase': 'P3-1b', 'status': 'FAIL', 'failure_stage': 'harness',
                  'failure_type': type(error).__name__}
    print(json.dumps(output, indent=2, sort_keys=True))
    sys.exit(0 if output['status'] == 'PASS' else 1)
