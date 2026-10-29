"""Integration assertions share ONE fresh Anvil run; no mocked cast or signatures.

Use scripts/run_p3_group1b_checks.py to run the suite without reading project .env.
Missing binaries/artifacts are failures, never skipped integration coverage.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope='module')
def real_smoke():
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/run_p3_group1b_smoke.py')],
                            capture_output=True, encoding='utf-8', errors='replace', timeout=300)
    # Harness output is allowlisted; never include child-process stderr in assertions.
    assert result.returncode == 0, result.stdout
    data = json.loads(result.stdout)
    assert data['status'] == 'PASS'
    if os.environ.get('P3_SMOKE_REPORT'):
        Path(os.environ['P3_SMOKE_REPORT']).write_text(result.stdout, encoding='utf-8')
    return data


def check(data, name):
    found = [item for item in data['checks'] if item['name'] == name]
    assert len(found) == 1 and found[0]['status'] == 'PASS', name
    return found[0]


def test_real_keystore_signs_anchor_and_custody(real_smoke):
    signer = check(real_smoke, 'real_keystore_address')['address']
    for kind in ('anchor', 'custody'):
        check(real_smoke, 'real_keystore_' + kind + '_receipt_db_chain')
        tx = [tx for tx in real_smoke['transactions'] if tx['kind'] == kind]
        assert len(tx) == 1 and tx[0]['from'] == signer
    check(real_smoke, 'contract_registered_by_and_custody_actor')


@pytest.mark.parametrize('kind', ['anchor', 'custody'])
@pytest.mark.parametrize('reason', ['from_mismatch', 'env_from_mismatch', 'no_bytecode',
    'live_chain_mismatch', 'non_anvil_client', 'wrong_password', 'missing_keystore',
    'nonlocal_http', 'nonlocal_https_local_transport', 'rpc_unavailable',
    'nonlocal_chain_requires_keystore'])
def test_real_guard_rejects_before_send(real_smoke, kind, reason):
    result = check(real_smoke, kind + '_' + reason)
    assert result['cast_send_calls'] == 0 and result['nonce_chain_db_unchanged']


@pytest.mark.parametrize('kind', ['anchor', 'custody'])
@pytest.mark.parametrize('index', range(10))
@pytest.mark.parametrize('chain', [11155111, 1])
def test_real_default_accounts_rejected_on_simulated_public_chain(real_smoke, kind, index, chain):
    check(real_smoke, 'ten_defaults_match_real_anvil')
    result = check(real_smoke, f'{kind}_default_{index}_simulated_chain_{chain}')
    assert result['cast_send_calls'] == 0 and result['nonce_chain_db_unchanged']


@pytest.mark.parametrize('kind', ['anchor', 'custody'])
def test_real_cli_from_mismatch(real_smoke, kind):
    assert check(real_smoke, kind + '_cli_from_mismatch')['exit_code'] == 1


@pytest.mark.parametrize('kind', ['anchor', 'custody'])
def test_real_unlocked_local_anvil(real_smoke, kind):
    check(real_smoke, 'unlocked_' + kind)


def test_real_cast_stderr_redaction(real_smoke):
    assert check(real_smoke, 'real_cast_rpc_stderr_log_audit_redaction')['canary_classes'] == 5


def test_real_smoke_preserves_inputs_and_cleans_wallet(real_smoke):
    assert real_smoke['original_samples_unchanged']
    assert real_smoke['temporary_keystore_removed']
    assert not real_smoke['public_rpc_used']
    assert real_smoke['chain_id'] == 31337
