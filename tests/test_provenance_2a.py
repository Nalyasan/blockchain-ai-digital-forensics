"""Real Git repositories for provenance; never mutate the user's repository."""
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from forensics import provenance as git


def command(root, *args):
    result = git._git(list(args), root)
    assert result.returncode == 0, 'Isolated Git operation failed'
    return result.stdout.decode().strip()


def commit(root, message):
    command(root, 'add', '--all')
    command(root, '-c', 'user.name=Isolated test', '-c', 'user.email=test@invalid',
            '-c', 'core.hooksPath=' + __import__('os').devnull, 'commit', '-qm', message)
    return command(root, 'rev-parse', 'HEAD')


@pytest.fixture
def repo(tmp_path):
    root = tmp_path/'repo'
    root.mkdir()
    command(root, 'init', '-q')
    (root/'file.txt').write_text('first')
    (root/'tracked.log').write_text('tracked')
    (root/'results').mkdir()
    (root/'results/tracked.log').write_text('tracked')
    commit(root, 'initial')
    return root


def test_clean_and_module_root_independent_of_cwd(repo, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state = git.get_git_state(repo)
    assert state.state == 'CLEAN' and state.head == command(repo, 'rev-parse', 'HEAD')
    assert Path(state.repo_root) == repo.resolve()
    monkeypatch.setattr(git, '__file__', str(repo/'forensics/provenance.py'))
    assert git.get_git_state().state == 'CLEAN'


@pytest.mark.parametrize('operation', ['modified','deleted','rename','untracked','tracked_results_log','outside_log'])
def test_dirty_paths_real_git(repo, operation):
    if operation == 'modified': (repo/'file.txt').write_text('changed')
    if operation == 'deleted': (repo/'file.txt').unlink()
    if operation == 'rename': command(repo, 'mv', 'file.txt', 'new name.txt')
    if operation == 'untracked': (repo/'untracked.txt').write_text('new')
    if operation == 'tracked_results_log': (repo/'results/tracked.log').write_text('changed')
    if operation == 'outside_log': (repo/'new.log').write_text('new')
    state = git.get_git_state(repo)
    assert state.state == 'DIRTY' and state.dirty_paths
    if operation == 'rename': assert set(state.dirty_paths) == {'file.txt','new name.txt'}


def test_only_untracked_results_logs_excluded(repo):
    (repo/'results/runtime.log').write_text('new')
    assert git.get_git_state(repo).state == 'CLEAN'
    (repo/'results/source.py').write_text('code')
    assert git.get_git_state(repo).dirty_paths == ('results/source.py',)


@pytest.mark.parametrize('raw', [b'M  new\0', b' D old\0', b'R  new name\0old name\0', b'C  copied\0source\0', b'?? untracked\0'])
def test_parse_status_modes(raw):
    assert git.parse_status(raw)


@pytest.mark.parametrize('raw', [b'M file', b'R  new\0', b'XY file\0', b'?? ../bad\0', b'?? \0'])
def test_malformed_status_rejected(raw):
    with pytest.raises(ValueError): git.parse_status(raw)


@pytest.mark.parametrize('failure', ['missing', 'timeout', 'bad-output'])
def test_git_errors_unknown(repo, monkeypatch, failure):
    if failure == 'missing':
        monkeypatch.setattr(git, '_git', Mock(side_effect=OSError('fake-token')))
    elif failure == 'timeout':
        monkeypatch.setattr(git, '_git', Mock(side_effect=subprocess.TimeoutExpired(['fake-token'], 10)))
    else:
        original = git._git
        def bad(args, root):
            if args[0] == 'status': return subprocess.CompletedProcess(args, 0, b'bad\0', b'')
            return original(args, root)
        monkeypatch.setattr(git, '_git', bad)
    state = git.get_git_state(repo)
    assert state.state == 'UNKNOWN' and 'fake-token' not in repr(state)


def test_no_repo_and_unborn_head_unknown(tmp_path):
    assert git.get_git_state(tmp_path).state == 'UNKNOWN'
    command(tmp_path, 'init', '-q')
    assert git.get_git_state(tmp_path).state == 'UNKNOWN'


def test_ancestry_and_divergent_commit(repo):
    initial = git.get_git_state(repo).head
    (repo/'file.txt').write_text('second')
    head = commit(repo, 'second')
    assert git.check_commit_provenance(initial, repo) == 'OK'
    assert git.check_commit_provenance(head, repo) == 'OK'
    command(repo, 'checkout', '-qb', 'divergent', initial)
    (repo/'side.txt').write_text('side')
    divergent = commit(repo, 'side')
    command(repo, 'checkout', '--detach', head)
    assert git.check_commit_provenance(divergent, repo) == 'MISMATCH'
    assert git.check_commit_provenance('f'*40, repo) == 'MISMATCH'
    assert git.check_commit_provenance('--bad-argument', repo) == 'MISMATCH'
    command(repo, 'pack-refs', '--all')
    assert git.get_git_state(repo).state == 'CLEAN'


def test_worktree_provenance(repo, tmp_path):
    work = tmp_path/'worktree'
    command(repo, 'worktree', 'add', '--detach', str(work))
    assert git.get_git_state(work).head == git.get_git_state(repo).head
    assert git.check_commit_provenance(git.get_git_state(repo).head, work) == 'OK'


def test_git_environment_and_timeout(repo, monkeypatch):
    monkeypatch.setenv('GIT_DIR', 'fake-outside-repository')
    original, calls = git.subprocess.run, []
    def record(*args, **kwargs):
        calls.append(kwargs)
        return original(*args, **kwargs)
    monkeypatch.setattr(git.subprocess, 'run', record)
    assert git.get_git_state(repo).state == 'CLEAN'
    assert all(c['shell'] is False and c['timeout'] == 10 and 'GIT_DIR' not in c['env'] for c in calls)


@pytest.mark.parametrize('failure', ['operational', 'malformed', 'timeout'])
def test_commit_lookup_errors_are_unknown(repo, monkeypatch, failure):
    head, original = git.get_git_state(repo).head, git._git
    def fail(args, root, input_data=None):
        if args[0] == 'cat-file':
            if failure == 'timeout': raise subprocess.TimeoutExpired(['git'], 10)
            return subprocess.CompletedProcess(args, 128 if failure == 'operational' else 0, b'bad-output', b'fake-token')
        return original(args, root, input_data)
    monkeypatch.setattr(git, '_git', fail)
    assert git.check_commit_provenance(head, repo) == 'UNKNOWN'


@pytest.mark.parametrize("trust", ["exact", "other", "wildcard", "relative"])
def test_explicit_repository_trust_is_path_scoped(repo, tmp_path, monkeypatch, trust):
    values = {"exact": str(repo.resolve()), "other": str(tmp_path / "other"),
              "wildcard": "*", "relative": "."}
    monkeypatch.setenv("FORENSICS_TRUSTED_REPOSITORY", values[trust])
    original, commands = git.subprocess.run, []
    def record(command, **kwargs):
        commands.append(command)
        return original(command, **kwargs)
    monkeypatch.setattr(git.subprocess, "run", record)
    assert git.get_git_state(repo).state == "CLEAN"
    flags = [arg for command in commands for arg in command if arg.startswith("safe.directory=")]
    assert bool(flags) == (trust == "exact")
    assert all(arg == "safe.directory=" + repo.resolve().as_posix() for arg in flags)
