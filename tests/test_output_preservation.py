import hashlib
import os
import subprocess
import pytest
from scripts.evidence_output import reserve_output

def test_output_reservation_and_preservation(tmp_path):
    protected=tmp_path/'old';protected.mkdir()
    proof=protected/'proof.txt';proof.write_bytes(b'original evidence')
    before=hashlib.sha256(proof.read_bytes()).hexdigest()
    existing=tmp_path/'exists';existing.mkdir()
    for target in (existing,protected,protected/'new'):
        with pytest.raises((ValueError,FileExistsError)):reserve_output(target,[protected])
    alias=tmp_path/'alias'
    try:
        try:alias.symlink_to(protected,target_is_directory=True)
        except OSError:
            assert os.name=='nt'
            result=subprocess.run(['cmd','/c','mklink','/J',str(alias),str(protected)],capture_output=True)
            assert result.returncode==0
        with pytest.raises(ValueError):reserve_output(alias/'new',[protected])
    finally:
        if os.path.lexists(alias):
            if alias.is_symlink():alias.unlink()
            else:os.rmdir(alias)
    output=reserve_output(tmp_path/'new',[protected]);(output/'proof').write_text('new')
    with pytest.raises(FileExistsError):reserve_output(output,[protected])
    assert hashlib.sha256(proof.read_bytes()).hexdigest()==before
