"""Run mandatory checks on a byte-identical source snapshot with NO project .env.

The snapshot includes only explicit source/fixture/tool allowlists. No project
credentials are read, copied, hashed or inherited. Foundry compilation is offline.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--pytest-path', type=Path, help='Optional directory containing pytest dependencies')
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    sources = [ROOT / 'collector.py', ROOT / 'mock_rpc.py', ROOT / 'contracts/foundry.toml']
    for folder, suffix in [('forensics', '*.py'), ('tests', '*.py'), ('scripts', '*.py'),
                           ('contracts/src', '*.sol'), ('contracts/test', '*.sol')]:
        sources += sorted((ROOT / folder).rglob(suffix))
    samples = [ROOT / 'results/p1/anvil_forensics.db']
    samples += sorted((ROOT / 'results/p2/case-anvil-p1-001').glob('*'))
    files = [p for p in sources + samples if p.is_file()]
    before = {str(p.relative_to(ROOT)): sha(p) for p in files}
    tool_suffix = '.exe' if os.name == 'nt' else ''
    evidence = {'source_sha256': before, 'project_env_accessed': False}
    with tempfile.TemporaryDirectory(prefix='p3-1b-checkout-') as folder:
        snapshot = Path(folder)
        for source in files:
            target = snapshot / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            if sha(target) != sha(source):
                raise RuntimeError('SNAPSHOT_HASH_MISMATCH')
        for name in ('cast', 'anvil', 'forge'):
            source = ROOT / 'tools/foundry' / (name + tool_suffix)
            target = snapshot / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        # Keep OS/toolchain discovery only. Never inherit RPC, wallet or API settings.
        allowed = {'SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC', 'TEMP', 'TMP',
                   'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH'}
        env = {k: v for k, v in os.environ.items() if k.upper() in allowed}
        env.update(PYTHONUTF8='1', PYTHONIOENCODING='utf-8', FOUNDRY_OFFLINE='true',
                   NO_PROXY='*', RPC_URL='http://127.0.0.1:1', ANCHOR_RPC_URL='http://127.0.0.1:1',
                   P3_SMOKE_REPORT=str(output / 'smoke.json'))
        if args.pytest_path:
            env['PYTHONPATH'] = str(args.pytest_path.resolve())
        # A real, isolated Git repository is required by fail-closed provenance.
        # Its commit identifies the snapshot; checks.json identifies product bytes.
        (snapshot / '.gitignore').write_text('tools/\nresults/\n__pycache__/\n*.pyc\n.pytest_cache/\ncontracts/out/\ncontracts/cache/\n', encoding='utf-8')
        git_env = dict(env, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
        for arguments in (['init', '-q'], ['add', '--', '.gitignore', 'collector.py', 'mock_rpc.py', 'forensics', 'tests', 'scripts', 'contracts'],
                          ['-c', 'user.name=P3 isolated test', '-c', 'user.email=test@invalid',
                           '-c', 'core.hooksPath=' + os.devnull, 'commit', '-qm', 'isolated test source']):
            result = subprocess.run(['git', *arguments], cwd=snapshot, env=git_env,
                                    capture_output=True, timeout=30)
            if result.returncode:
                raise RuntimeError('ISOLATED_GIT_SETUP_FAILED')
        evidence['isolated_git_head'] = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=snapshot,
            env=git_env, capture_output=True, text=True, check=True).stdout.strip()
        env['P3_2A_EVIDENCE_DIR'] = str(output)
        forge = str(snapshot / 'tools/foundry' / ('forge' + tool_suffix))
        # Compile from this exact snapshot first so integration deploys its artifact.
        commands = [('forge', [forge, 'test', '--root', 'contracts']),
                    ('pytest', [sys.executable, '-m', 'pytest', 'tests/', '-q'])]
        for name, command in commands:
            print('Running ' + name + ' in isolated source snapshot', flush=True)
            result = subprocess.run(command, cwd=snapshot, env=env, capture_output=True,
                                    encoding='utf-8', errors='replace', timeout=480)
            (output / (name + '.txt')).write_text(result.stdout + result.stderr, encoding='utf-8')
            evidence[name + '_exit_code'] = result.returncode
            print(name + '_exit=' + str(result.returncode), flush=True)
        # Tests may leave Python sqlite references until process exit; children have exited.
    evidence['source_and_samples_unchanged'] = before == {str(p.relative_to(ROOT)): sha(p) for p in files}
    evidence['status'] = 'PASS' if evidence['source_and_samples_unchanged'] and all(
        evidence[name + '_exit_code'] == 0 for name in ('pytest', 'forge')) else 'FAIL'
    (output / 'checks.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    print('P3-1b checks: ' + evidence['status'])
    return 0 if evidence['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
