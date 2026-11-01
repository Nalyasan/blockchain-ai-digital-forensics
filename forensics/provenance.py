"""Bounded, repository-relative Git provenance. Never reads project .env."""
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import subprocess


@dataclass(frozen=True)
class GitState:
    state: str
    head: str | None = None
    repo_root: str | None = None
    dirty_paths: tuple[str, ...] = ()


def _git(args, root, input_data=None):
    executable = shutil.which('git')
    if not executable:
        for candidate in (
            r"C:\Program Files\Git\cmd\git.exe",
            r"C:\Program Files\Git\bin\git.exe",
        ):
            if os.path.exists(candidate):
                executable = candidate
                break
    if not executable:
        raise OSError('GIT_UNAVAILABLE')
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1')
    trust_args = []
    # Explicit process-local trust for a reviewed integration checkout. Never
    # inherit wildcard Git trust or trust unrelated repositories automatically.
    trusted = os.environ.get('FORENSICS_TRUSTED_REPOSITORY')
    if trusted and Path(trusted).is_absolute() and Path(trusted).resolve() == Path(root).resolve():
        trust_args = ['-c', 'safe.directory=' + Path(root).resolve().as_posix()]
    return subprocess.run([executable, '-c', 'core.fsmonitor=false', *trust_args, *args], cwd=root, env=env, shell=False,
                          timeout=10, capture_output=True, check=False, input=input_data)


def parse_status(raw: bytes) -> tuple[str, ...]:
    if raw and not raw.endswith(b'\0'):
        raise ValueError('GIT_STATUS_INVALID')
    parts = raw.split(b'\0')[:-1]
    paths, i = [], 0
    while i < len(parts):
        entry = parts[i].decode('utf-8', errors='strict')
        i += 1
        if len(entry) < 4 or entry[2] != ' ':
            raise ValueError('GIT_STATUS_INVALID')
        status, path = entry[:2], entry[3:]
        if status not in ('??', '!!') and (any(c not in ' MADRCUT?!' for c in status) or status == '  '):
            raise ValueError('GIT_STATUS_INVALID')
        if not path or path.startswith('/') or '..' in path.split('/'):
            raise ValueError('GIT_STATUS_INVALID')
        # Only untracked runtime logs under results may be excluded.
        if not (status == '??' and path.startswith('results/') and path.endswith('.log')):
            paths.append(path)
        if 'R' in status or 'C' in status:
            if i >= len(parts) or not parts[i]:
                raise ValueError('GIT_STATUS_INVALID')
            paths.append(parts[i].decode('utf-8', errors='strict'))
            i += 1
    return tuple(paths)


def get_git_state(repo_root=None) -> GitState:
    root = Path(repo_root) if repo_root is not None else Path(__file__).resolve().parents[1]
    try:
        top = _git(['rev-parse', '--show-toplevel'], root)
        if top.returncode:
            return GitState('UNKNOWN')
        resolved = Path(top.stdout.decode('utf-8').strip()).resolve()
        if not root.resolve().is_relative_to(resolved):
            return GitState('UNKNOWN')
        head = _git(['rev-parse', '--verify', 'HEAD'], resolved)
        status = _git(['status', '--porcelain=v1', '-z', '--untracked-files=all'], resolved)
        value = head.stdout.decode('ascii').strip()
        if head.returncode or status.returncode or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', value):
            return GitState('UNKNOWN')
        paths = parse_status(status.stdout)
        return GitState('DIRTY' if paths else 'CLEAN', value, str(resolved), paths)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return GitState('UNKNOWN')


def check_commit_provenance(export_commit, repo_root) -> str:
    if not isinstance(export_commit, str) or not re.fullmatch(r'[0-9a-fA-F]{40}|[0-9a-fA-F]{64}', export_commit):
        return 'MISMATCH'
    state = get_git_state(repo_root)
    if state.state == 'UNKNOWN':
        return 'UNKNOWN'
    try:
        # --batch-check separates a missing object from a Git operational error.
        exists = _git(['cat-file', '--batch-check=%(objecttype)'], state.repo_root,
                      (export_commit + '\n').encode('ascii'))
        if exists.returncode:
            return 'UNKNOWN'
        kind = exists.stdout.strip()
        if kind == (export_commit + ' missing').encode('ascii') or kind in (b'blob', b'tree', b'tag'):
            return 'MISMATCH'
        if kind != b'commit':
            return 'UNKNOWN'
        ancestor = _git(['merge-base', '--is-ancestor', export_commit, state.head], state.repo_root)
        return {0: 'OK', 1: 'MISMATCH'}.get(ancestor.returncode, 'UNKNOWN')
    except (OSError, subprocess.SubprocessError):
        return 'UNKNOWN'


def inspect_commit_provenance(export_commit, repo_root=None):
    """Detailed write policy; only a proven existing non-ancestor is overridable."""
    root = Path(repo_root) if repo_root is not None else Path(__file__).resolve().parents[1]
    state = get_git_state(root)
    result = {'status': 'INDETERMINATE', 'head': state.head, 'git_state': state.state,
              'repo_root': state.repo_root}
    if state.state == 'UNKNOWN':
        return result
    if Path(state.repo_root).resolve() != root.resolve():
        return dict(result, status='WRONG_REPOSITORY')
    if not isinstance(export_commit, str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', export_commit):
        return dict(result, status='MALFORMED')
    try:
        graft = _git(['rev-parse', '--git-path', 'info/grafts'], root)
        if graft.returncode:
            return result
        graft_path = Path(graft.stdout.decode().strip())
        if not graft_path.is_absolute():
            graft_path = root / graft_path
        if graft_path.exists():
            return result
        shallow = _git(['rev-parse', '--is-shallow-repository'], root)
        # Conservative: never infer a divergent history from a truncated graph.
        if shallow.returncode or shallow.stdout.strip() != b'false':
            return result
        obj = _git(['cat-file', '--batch-check=%(objecttype)'], root, (export_commit+'\n').encode('ascii'))
        if obj.returncode:
            return result
        if obj.stdout.strip() == (export_commit+' missing').encode():
            return dict(result, status='MISSING')
        if obj.stdout.strip() != b'commit':
            return dict(result, status='WRONG_OBJECT_TYPE')
        ancestor = _git(['merge-base', '--is-ancestor', export_commit, state.head], root)
        return dict(result, status={0:'OK',1:'EXISTING_NON_ANCESTOR'}.get(ancestor.returncode,'INDETERMINATE'))
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return result
