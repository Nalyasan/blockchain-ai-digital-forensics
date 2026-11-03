import json
import sqlite3
from pathlib import Path
import pytest
from forensics.evaluation import confusion, validate_labels, evaluate_database, wilson_review
from forensics.paths import REAL_P4_DB

def label_doc(labels):
    return {'schema_version':1,'synthetic':False,'labels':[
        {'unit_type':kind,'unit_key':key,'positive':value,'source_url':'https://example.org/review',
         'accessed_at':'2026-11-02T00:00:00Z'} for kind,key,value in labels]}

def test_confusion_mixed_and_empty_denominators():
    m=confusion({'a':True,'b':False,'c':True,'d':False},{'a','b'})
    assert [m[k] for k in ('TP','FP','TN','FN')]==[1,1,1,1]
    assert m['f1']==0.5
    assert confusion({},set())['fpr'] is None

@pytest.mark.parametrize('field,value',[('source_url',''),('accessed_at','2026-11-02'),('positive','yes')])
def test_labels_require_explicit_provenance(field,value):
    d=label_doc([('tx_unit','x',True)]);d['labels'][0][field]=value
    with pytest.raises(ValueError): validate_labels(d)

def test_duplicate_labels_rejected():
    d=label_doc([('tx_unit','x',True),('tx_unit','x',False)])
    with pytest.raises(ValueError,match='DUPLICATE'): validate_labels(d)

def test_real_readonly_evaluation_partial_labels_and_no_db_mutation():
    import hashlib
    before=hashlib.sha256(REAL_P4_DB.read_bytes()).hexdigest()
    with sqlite3.connect(REAL_P4_DB.as_uri()+'?mode=ro',uri=True) as c:
        c.row_factory=sqlite3.Row
        c.execute('pragma query_only=ON')
        tx=c.execute('select tx_hash from asset_transfers where block_number between 16817990 and 16818110 limit 1').fetchone()[0]
        # Deliberately synthetic evaluation assertion, not a real-world label claim.
        d=label_doc([('tx_unit',tx,True)])
        report=evaluate_database(c,d,(16816000,16817989),(16817990,16818110))
        assert report['units']['tx_unit']['status']=='LABELED_SUBSET_ONLY'
        assert report['units']['address_window_unit']['status']=='NOT_EVALUATED'
        assert report['generated_alerts']>0
        with pytest.raises(ValueError,match='CALIBRATION'):
            evaluate_database(c,d,(16816000,16817990),(16817990,16818110))
        d['synthetic']=True
        with pytest.raises(ValueError,match='SYNTHETIC'):
            evaluate_database(c,d,(16816000,16817989),(16817990,16818110))
    assert hashlib.sha256(REAL_P4_DB.read_bytes()).hexdigest()==before

def test_wilson_is_not_detection_recall():
    r=wilson_review(8,10)
    assert r['estimated_precision']==0.8
    assert 0<r['wilson_95'][0]<0.8<r['wilson_95'][1]<1
    assert r['recall'] is None and r['fpr'] is None
