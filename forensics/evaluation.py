"""Evidence-based evaluation. Unknown labels are never inferred to be benign."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import math
from urllib.parse import urlparse


def validate_labels(document):
    if document.get('schema_version') != 1:
        raise ValueError('LABEL_SCHEMA_VERSION')
    if type(document.get('synthetic')) is not bool:
        raise ValueError('SYNTHETIC_FLAG_REQUIRED')
    labels = document.get('labels')
    if not isinstance(labels, list) or not labels:
        raise ValueError('LABELS_REQUIRED')
    seen = set()
    for row in labels:
        kind, key = row.get('unit_type'), row.get('unit_key')
        if kind not in ('tx_unit', 'address_window_unit') or not isinstance(key, str) or not key:
            raise ValueError('INVALID_LABEL_UNIT')
        if type(row.get('positive')) is not bool:
            raise ValueError('EXPLICIT_BINARY_LABEL_REQUIRED')
        if (kind, key) in seen:
            raise ValueError('DUPLICATE_LABEL')
        seen.add((kind, key))
        url = urlparse(row.get('source_url', ''))
        if url.scheme not in ('http', 'https') or not url.netloc:
            raise ValueError('SOURCE_URL_REQUIRED')
        stamp = datetime.fromisoformat(row.get('accessed_at', '').replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise ValueError('SOURCE_TIMESTAMP_TIMEZONE_REQUIRED')
    return document


def confusion(actual, predicted):
    counts = dict(TP=0, FP=0, TN=0, FN=0)
    for key, positive in actual.items():
        counts[('TP' if positive else 'FP') if key in predicted else ('FN' if positive else 'TN')] += 1
    tp, fp, tn, fn = (counts[k] for k in ('TP', 'FP', 'TN', 'FN'))
    div = lambda a, b: a / b if b else None
    return {**counts, 'precision': div(tp, tp+fp), 'recall': div(tp, tp+fn),
            'fpr': div(fp, fp+tn), 'f1': div(2*tp, 2*tp+fp+fn)}


def evaluate_database(conn, labels, calibration, test, *, chain_id=1, bucket_size=900):
    """Run rules read-only, then evaluate canonical units with explicit labels.

    Partial labels produce LABELED_SUBSET_ONLY, never full-cohort accuracy.
    Recalibration uses only the earlier window and never writes evidence.
    """
    validate_labels(labels)
    if bucket_size <= 0 or calibration[0] > calibration[1] or test[0] > test[1] or calibration[1] >= test[0]:
        raise ValueError('CALIBRATION_MUST_PRECEDE_TEST')
    rows = conn.execute('''SELECT t.tx_hash,t.from_addr,t.to_addr,t.block_timestamp,t.synthetic
        FROM asset_transfers t JOIN blocks b ON t.chain_id=b.chain_id AND t.block_hash=b.hash
        WHERE t.chain_id=? AND t.block_number BETWEEN ? AND ? AND b.status='canonical' ''',
        (chain_id, *test)).fetchall()
    if not rows:
        raise ValueError('EMPTY_TEST_COHORT')
    if {bool(r[4]) for r in rows} != {labels['synthetic']}:
        raise ValueError('SYNTHETIC_REAL_MIX_OR_MISMATCH')
    units = {'tx_unit': set(), 'address_window_unit': set()}
    address_buckets = defaultdict(set)
    for tx, sender, receiver, stamp, _ in rows:
        units['tx_unit'].add(tx.lower())
        for address in (sender, receiver):
            if address:
                key = address.lower()
                bucket = int(stamp) // bucket_size
                address_buckets[key].add(bucket)
                units['address_window_unit'].add(f'{key}:{bucket}')
    from forensics.rules.engine import RuleEngine
    alerts = RuleEngine(conn, chain_id=chain_id).run(
        test_start_block=test[0], test_end_block=test[1],
        cal_start_block=calibration[0], cal_end_block=calibration[1], persist=False)
    predictions = defaultdict(lambda: {'tx_unit': set(), 'address_window_unit': set()})
    for alert in alerts:
        rule, kind, key = alert.rule_id, alert.unit_type, alert.unit_key
        start = datetime.fromisoformat(alert.window_start.replace('Z','+00:00')).timestamp()
        end = datetime.fromisoformat(alert.window_end.replace('Z','+00:00')).timestamp()
        references = alert.evidence_refs
        relevant = [r for r in references if r.get('chain_id') == chain_id and test[0] <= r.get('block_number', -1) <= test[1]]
        if not relevant:
            continue
        for group in (rule, 'union'):
            predictions[group]['tx_unit'].update(r['tx_hash'].lower() for r in relevant if r['tx_hash'].lower() in units['tx_unit'])
            if kind == 'address_window':
                # Use the alert's subject, never infer that every counterparty was flagged.
                parts=key.split(':')
                address = parts[2 if rule=='fan_in_out' else 1].lower()
                for bucket in address_buckets.get(address, ()):
                    if int(start) < (bucket+1)*bucket_size and int(end) >= bucket*bucket_size:
                        predictions[group]['address_window_unit'].add(f'{address}:{bucket}')
    by_kind = {k: {} for k in units}
    for row in labels['labels']:
        kind, key = row['unit_type'], row['unit_key'].lower()
        if key not in units[kind]:
            raise ValueError('LABEL_OUTSIDE_TEST_COHORT')
        by_kind[kind][key] = row['positive']
    report = {'synthetic': labels['synthetic'], 'calibration_window': list(calibration),
              'test_window': list(test), 'chain_id': chain_id, 'bucket_size': bucket_size,
              'calibration_provenance': 'recomputed read-only from the specified earlier window',
              'generated_alerts': len(alerts), 'units': {}}
    for kind, universe in units.items():
        truth = by_kind[kind]
        report['units'][kind] = {
            'status': 'NOT_EVALUATED' if not truth else ('COMPLETE' if len(truth)==len(universe) else 'LABELED_SUBSET_ONLY'),
            'cohort_size': len(universe), 'labeled': len(truth), 'unknown': len(universe)-len(truth),
            'metrics': {g: confusion(truth, predictions[g][kind]) for g in ('large_transfer','high_frequency','fan_in_out','rapid_pass_through','union')} if truth else None}
    return report


def wilson_review(positive, total):
    if not 0 <= positive <= total or total <= 0:
        raise ValueError('INVALID_REVIEW_COUNTS')
    z=1.959963984540054
    p=positive/total; denominator=1+z*z/total
    center=(p+z*z/(2*total))/denominator
    margin=z*math.sqrt(p*(1-p)/total+z*z/(4*total*total))/denominator
    return {'reviewed': total, 'true_positive': positive, 'estimated_precision': p,
            'wilson_95': [center-margin, center+margin], 'recall': None, 'fpr': None}
