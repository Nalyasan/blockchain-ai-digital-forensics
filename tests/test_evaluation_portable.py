from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

import pytest

from forensics.evaluation import (
    confusion,
    evaluate_database,
    validate_labels,
    wilson_review,
)
from forensics.paths import (
    DATA_DIR,
    PROJECT_ROOT,
    REAL_P4_DB,
    TOOLS_DIR,
    get_data_dir,
    get_project_root,
    get_tools_dir,
)
import scripts.evaluate as eval_script


def label_doc(labels, synthetic=False):
    return {
        'schema_version': 1,
        'synthetic': synthetic,
        'labels': [
            {
                'unit_type': kind,
                'unit_key': key,
                'positive': value,
                'source_url': 'https://example.org/review',
                'accessed_at': '2026-11-02T00:00:00Z',
            }
            for kind, key, value in labels
        ],
    }


def test_confusion_mixed_and_empty_denominators():
    m = confusion({'a': True, 'b': False, 'c': True, 'd': False}, {'a', 'b'})
    assert [m[k] for k in ('TP', 'FP', 'TN', 'FN')] == [1, 1, 1, 1]
    assert m['f1'] == 0.5
    empty_m = confusion({}, set())
    assert empty_m['fpr'] == "N/A: No negative instances (TN + FP = 0)"
    assert empty_m['precision'] == "N/A: No positive predictions (TP + FP = 0)"
    assert empty_m['recall'] == "N/A: No positive ground truth labels (TP + FN = 0)"
    assert empty_m['f1'] == "N/A: Precision or Recall is undefined"


def test_zero_denominator_na_formatting_all_cases():
    # 1. No positive predictions (TP + FP = 0)
    m1 = confusion({'a': True, 'b': False}, set())
    assert m1['TP'] == 0 and m1['FP'] == 0 and m1['TN'] == 1 and m1['FN'] == 1
    assert m1['precision'] == "N/A: No positive predictions (TP + FP = 0)"
    assert m1['recall'] == 0.0
    assert m1['fpr'] == 0.0
    assert m1['f1'] == "N/A: Precision or Recall is undefined"

    # 2. No positive ground truth labels (TP + FN = 0)
    m2 = confusion({'b': False}, {'b'})
    assert m2['TP'] == 0 and m2['FP'] == 1 and m2['TN'] == 0 and m2['FN'] == 0
    assert m2['precision'] == 0.0
    assert m2['recall'] == "N/A: No positive ground truth labels (TP + FN = 0)"
    assert m2['fpr'] == 1.0
    assert m2['f1'] == "N/A: Precision or Recall is undefined"

    # 3. No negative instances in ground truth (TN + FP = 0)
    m3 = confusion({'a': True}, {'a'})
    assert m3['TP'] == 1 and m3['FP'] == 0 and m3['TN'] == 0 and m3['FN'] == 0
    assert m3['precision'] == 1.0
    assert m3['recall'] == 1.0
    assert m3['fpr'] == "N/A: No negative instances (TN + FP = 0)"
    assert m3['f1'] == 1.0

    # 4. Wilson review N = 0
    r_zero = wilson_review(0, 0)
    assert r_zero['reviewed'] == 0
    assert r_zero['true_positive'] == 0
    assert r_zero['estimated_precision'] == "N/A: No reviewed sample items (N = 0)"
    assert r_zero['wilson_95'] == "N/A: No reviewed sample items (N = 0)"
    assert r_zero['recall'] is None and r_zero['fpr'] is None

    # 5. Wilson review invalid counts
    with pytest.raises(ValueError, match='INVALID_REVIEW_COUNTS'):
        wilson_review(-1, 10)
    with pytest.raises(ValueError, match='INVALID_REVIEW_COUNTS'):
        wilson_review(11, 10)
    with pytest.raises(ValueError, match='INVALID_REVIEW_COUNTS'):
        wilson_review(1, 0)


@pytest.mark.parametrize('field,value', [('source_url', ''), ('accessed_at', '2026-11-02'), ('positive', 'yes')])
def test_labels_require_explicit_provenance(field, value):
    d = label_doc([('tx_unit', 'x', True)])
    d['labels'][0][field] = value
    with pytest.raises(ValueError):
        validate_labels(d)


def test_duplicate_labels_rejected():
    d = label_doc([('tx_unit', 'x', True), ('tx_unit', 'x', False)])
    with pytest.raises(ValueError, match='DUPLICATE'):
        validate_labels(d)


def test_real_readonly_evaluation_partial_labels_and_no_db_mutation():
    before = hashlib.sha256(REAL_P4_DB.read_bytes()).hexdigest()
    with sqlite3.connect(REAL_P4_DB.as_uri() + '?mode=ro', uri=True) as c:
        c.row_factory = sqlite3.Row
        c.execute('pragma query_only=ON')
        tx = c.execute(
            'select tx_hash from asset_transfers where block_number between 16817990 and 16818110 limit 1'
        ).fetchone()[0]
        d = label_doc([('tx_unit', tx, True)])
        report = evaluate_database(c, d, (16816000, 16817989), (16817990, 16818110))
        assert report['units']['tx_unit']['status'] == 'LABELED_SUBSET_ONLY'
        assert report['units']['address_window_unit']['status'] == 'NOT_EVALUATED'
        assert report['generated_alerts'] > 0
        with pytest.raises(ValueError, match='CALIBRATION'):
            evaluate_database(c, d, (16816000, 16817990), (16817990, 16818110))
        d['synthetic'] = True
        with pytest.raises(ValueError, match='SYNTHETIC'):
            evaluate_database(c, d, (16816000, 16817989), (16817990, 16818110))
    assert hashlib.sha256(REAL_P4_DB.read_bytes()).hexdigest() == before


def test_address_window_unit_evaluation_with_ground_truth():
    with sqlite3.connect(REAL_P4_DB.as_uri() + '?mode=ro', uri=True) as c:
        c.row_factory = sqlite3.Row
        c.execute('pragma query_only=ON')

        # Euler test window
        test_window = (16817990, 16818110)
        cal_window = (16816000, 16817989)

        # Get an address and its bucket from test window
        row = c.execute(
            'SELECT from_addr, block_timestamp FROM asset_transfers '
            'WHERE block_number BETWEEN ? AND ? AND from_addr IS NOT NULL LIMIT 1',
            test_window,
        ).fetchone()
        addr = row['from_addr'].lower()
        bucket = row['block_timestamp'] // 900
        aw_key = f'{addr}:{bucket}'

        tx = c.execute(
            'SELECT tx_hash FROM asset_transfers WHERE block_number BETWEEN ? AND ? LIMIT 1',
            test_window,
        ).fetchone()['tx_hash'].lower()

        d = label_doc([
            ('tx_unit', tx, True),
            ('address_window_unit', aw_key, True),
        ])

        # Evaluate both
        report = evaluate_database(c, d, cal_window, test_window, bucket_size=900)
        assert report['units']['tx_unit']['status'] == 'LABELED_SUBSET_ONLY'
        assert report['units']['address_window_unit']['status'] == 'LABELED_SUBSET_ONLY'
        assert report['units']['address_window_unit']['labeled'] == 1
        assert report['units']['address_window_unit']['cohort_size'] > 0
        aw_metrics = report['units']['address_window_unit']['metrics']
        assert aw_metrics is not None
        assert 'union' in aw_metrics
        assert isinstance(aw_metrics['union']['TP'], int)

        # Evaluate with unit_filter
        filtered_report = evaluate_database(c, d, cal_window, test_window, unit_filter='address_window_unit')
        assert list(filtered_report['units'].keys()) == ['address_window_unit']


def test_wilson_is_not_detection_recall():
    r = wilson_review(8, 10)
    assert r['estimated_precision'] == 0.8
    assert 0 < r['wilson_95'][0] < 0.8 < r['wilson_95'][1] < 1
    assert r['recall'] is None and r['fpr'] is None


def test_paths_contract_and_env_override(monkeypatch, tmp_path):
    assert get_project_root() == PROJECT_ROOT
    assert get_tools_dir() == TOOLS_DIR == PROJECT_ROOT / 'tools'
    assert get_data_dir() == PROJECT_ROOT / 'data'

    custom_data = tmp_path / 'custom_data'
    monkeypatch.setenv('FORENSICS_DATA_DIR', str(custom_data))
    assert get_data_dir() == custom_data.resolve()


def test_fetch_labels_creates_destination_dir(tmp_path):
    label_path = tmp_path / 'source_labels.json'
    label_path.write_text(json.dumps(label_doc([('tx_unit', '0xabc', True)])), encoding='utf-8')
    nested_out = tmp_path / 'nested' / 'dir' / 'output.json'
    assert not nested_out.parent.exists()

    script_path = PROJECT_ROOT / 'scripts' / 'fetch_labels.py'
    res = subprocess.run([sys.executable, str(script_path), str(label_path), '--out', str(nested_out)],
                         capture_output=True, text=True)
    assert res.returncode == 0
    assert nested_out.exists()
    data = json.loads(nested_out.read_text(encoding='utf-8'))
    assert data['schema_version'] == 1


def test_fetch_labels_offline_and_safe_overwrite(tmp_path, monkeypatch):
    script_path = PROJECT_ROOT / 'scripts' / 'fetch_labels.py'
    label_path = tmp_path / 'source_labels.json'
    label_path.write_text(json.dumps(label_doc([('tx_unit', '0x123', True)])), encoding='utf-8')
    out_file = tmp_path / 'out.json'

    # Run first time
    res1 = subprocess.run([sys.executable, str(script_path), str(label_path), '--out', str(out_file)],
                          capture_output=True, text=True)
    assert res1.returncode == 0
    assert out_file.exists()

    # Safe overwrite ('w'): run second time into same destination
    res2 = subprocess.run([sys.executable, str(script_path), str(label_path), '--out', str(out_file)],
                          capture_output=True, text=True)
    assert res2.returncode == 0

    # Offline mode with URL: should not hang, returns non-zero gracefully
    env = os.environ.copy()
    env['FORENSICS_OFFLINE'] = '1'
    res3 = subprocess.run(
        [sys.executable, str(script_path), 'https://nonexistent.domain.example/labels.json', '--out', str(tmp_path / 'url.json')],
        capture_output=True, text=True, env=env, timeout=15
    )
    assert res3.returncode != 0
    assert 'OFFLINE' in res3.stderr or 'ERROR' in res3.stderr


def test_generate_benchmark_help_exits_zero_without_output():
    script_path = PROJECT_ROOT / 'scripts' / 'generate_benchmark.py'
    res = subprocess.run([sys.executable, str(script_path), '--help'],
                         capture_output=True, text=True)
    assert res.returncode == 0
    assert 'usage: generate_benchmark.py' in res.stdout
    assert 'passed in' not in res.stdout.lower()


def test_generate_benchmark_default_out_is_temporary(tmp_path, monkeypatch):
    import uuid
    # Verify generate_benchmark uses tempdir when --out is omitted
    # Mock subprocess.run inside generate_benchmark to avoid running full pytest suite
    script_file = PROJECT_ROOT / 'scripts' / 'generate_benchmark.py'
    out_tmp = tmp_path / 'bench_out'
    res = subprocess.run(
        [sys.executable, str(script_file), '--out', str(out_tmp)],
        capture_output=True, text=True
    )
    assert res.returncode == 0
    assert (out_tmp / 'summary.json').exists()
    summary = json.loads((out_tmp / 'summary.json').read_text(encoding='utf-8'))
    assert summary['synthetic'] is True
    assert summary['real_world_precision'] is None


def test_evaluate_cli_incident_mode_euler(tmp_path):
    out_dir = tmp_path / 'euler_eval'
    cmd = [
        sys.executable, str(PROJECT_ROOT / 'scripts' / 'evaluate.py'),
        '--mode', 'incident',
        '--data', str(REAL_P4_DB),
        '--incident', 'euler',
        '--output', str(out_dir),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Error: {res.stderr}"

    json_path = out_dir / 'summary.json'
    csv_path = out_dir / 'summary.csv'
    assert json_path.exists()
    assert csv_path.exists()

    report = json.loads(json_path.read_text(encoding='utf-8'))
    assert report['mode'] == 'incident'
    assert report['incident'] == 'euler'
    assert report['synthetic'] is False
    assert 'tx_unit' in report['units']
    assert 'address_window_unit' in report['units']
    assert report['units']['tx_unit']['status'] == 'LABELED_SUBSET_ONLY'

    # Check CSV content
    csv_content = csv_path.read_text(encoding='utf-8')
    assert 'unit_type,rule,TP,FP,TN,FN,precision,recall,fpr,f1' in csv_content
    assert 'tx_unit' in csv_content
    assert 'address_window_unit' in csv_content

    # Safe overwrite: execute again into same directory
    res_overwrite = subprocess.run(cmd, capture_output=True, text=True)
    assert res_overwrite.returncode == 0


def test_evaluate_cli_incident_mode_curve_unit_filter(tmp_path):
    out_dir = tmp_path / 'curve_tx_only'
    cmd = [
        sys.executable, str(PROJECT_ROOT / 'scripts' / 'evaluate.py'),
        '--mode', 'incident',
        '--data', str(REAL_P4_DB),
        '--incident', 'curve',
        '--unit', 'tx_unit',
        '--output', str(out_dir),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Error: {res.stderr}"

    report = json.loads((out_dir / 'summary.json').read_text(encoding='utf-8'))
    assert list(report['units'].keys()) == ['tx_unit']

    csv_content = (out_dir / 'summary.csv').read_text(encoding='utf-8')
    assert 'tx_unit' in csv_content
    assert 'address_window_unit' not in csv_content


def test_evaluate_cli_sepolia_mode(tmp_path):
    out_dir = tmp_path / 'sepolia_eval'
    cmd = [
        sys.executable, str(PROJECT_ROOT / 'scripts' / 'evaluate.py'),
        '--mode', 'sepolia',
        '--data', str(REAL_P4_DB),
        '--output', str(out_dir),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Error: {res.stderr}"

    report = json.loads((out_dir / 'summary.json').read_text(encoding='utf-8'))
    assert report['mode'] == 'sepolia'
    assert report['synthetic'] is False
    assert 'review_sample' in report
    metrics = report['units']['tx_unit']['metrics']['union']
    assert str(metrics['recall']).startswith('N/A')
    assert str(metrics['fpr']).startswith('N/A')


def test_evaluate_cli_benchmark_mode(tmp_path):
    out_dir = tmp_path / 'bench_eval'
    cmd = [
        sys.executable, str(PROJECT_ROOT / 'scripts' / 'evaluate.py'),
        '--mode', 'benchmark',
        '--data', str(REAL_P4_DB),
        '--output', str(out_dir),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Error: {res.stderr}"

    report = json.loads((out_dir / 'summary.json').read_text(encoding='utf-8'))
    assert report['mode'] == 'benchmark'
    assert report['synthetic'] is True
    assert report['real_world_precision'] is None


def test_evaluate_cli_backward_compatibility(tmp_path):
    # Tests legacy flags: --db, --labels, --calibration, --test, --out
    with sqlite3.connect(REAL_P4_DB.as_uri() + '?mode=ro', uri=True) as c:
        tx = c.execute(
            'SELECT tx_hash FROM asset_transfers WHERE block_number BETWEEN 16817990 AND 16818110 LIMIT 1'
        ).fetchone()[0]

    label_file = tmp_path / 'custom_labels.json'
    label_file.write_text(json.dumps(label_doc([('tx_unit', tx, True)])), encoding='utf-8')
    out_file = tmp_path / 'legacy_out.json'

    cmd = [
        sys.executable, str(PROJECT_ROOT / 'scripts' / 'evaluate.py'),
        '--db', str(REAL_P4_DB),
        '--labels', str(label_file),
        '--calibration', '16816000', '16817989',
        '--test', '16817990', '16818110',
        '--out', str(out_file),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Error: {res.stderr}"
    assert out_file.exists()
    assert (tmp_path / 'legacy_out.csv').exists()

    report = json.loads(out_file.read_text(encoding='utf-8'))
    assert report['units']['tx_unit']['status'] == 'LABELED_SUBSET_ONLY'


def test_evaluate_cli_error_handling(tmp_path):
    script = str(PROJECT_ROOT / 'scripts' / 'evaluate.py')

    # 1. Missing database
    res1 = subprocess.run(
        [sys.executable, script, '--data', str(tmp_path / 'no_db.db'), '--output', str(tmp_path / 'out')],
        capture_output=True, text=True
    )
    assert res1.returncode != 0
    assert 'Database not found' in res1.stderr

    # 2. Overlapping calibration and test window
    with sqlite3.connect(REAL_P4_DB.as_uri() + '?mode=ro', uri=True) as c:
        tx = c.execute(
            'SELECT tx_hash FROM asset_transfers WHERE block_number BETWEEN 16817990 AND 16818110 LIMIT 1'
        ).fetchone()[0]
    label_file = tmp_path / 'labels.json'
    label_file.write_text(json.dumps(label_doc([('tx_unit', tx, True)])), encoding='utf-8')

    res2 = subprocess.run(
        [sys.executable, script, '--data', str(REAL_P4_DB), '--labels', str(label_file),
         '--calibration', '16816000', '16817990', '--test', '16817990', '16818110',
         '--output', str(tmp_path / 'overlap')],
        capture_output=True, text=True
    )
    assert res2.returncode != 0
    assert 'CALIBRATION_MUST_PRECEDE_TEST' in res2.stderr

    # 3. Synthetic mismatch
    synth_label_file = tmp_path / 'synth_labels.json'
    synth_label_file.write_text(json.dumps(label_doc([('tx_unit', tx, True)], synthetic=True)), encoding='utf-8')

    res3 = subprocess.run(
        [sys.executable, script, '--data', str(REAL_P4_DB), '--labels', str(synth_label_file),
         '--calibration', '16816000', '16817989', '--test', '16817990', '16818110',
         '--output', str(tmp_path / 'synth_err')],
        capture_output=True, text=True
    )
    assert res3.returncode != 0
    assert 'SYNTHETIC_REAL_MIX_OR_MISMATCH' in res3.stderr

    # 4. Invalid mode
    res4 = subprocess.run(
        [sys.executable, script, '--mode', 'invalid_mode', '--output', str(tmp_path / 'invalid')],
        capture_output=True, text=True
    )
    assert res4.returncode != 0
    assert 'invalid choice' in res4.stderr
