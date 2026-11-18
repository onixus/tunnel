"""Fixed-argument host commands and crash-safe files for the root agent.

Callers pass an argument vector, never a shell command line, and the only text a
failed command contributes to an error is the program name. `agent`, `amnezia`
and `cdn` keep thin wrappers so each raises its own exception type and so tests
can still patch `run`, `write` and `load` on the module that owns them.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess


def run(args, timeout=30, env=None, error=RuntimeError):
    completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
    if completed.returncode:
        raise error('Операция не завершена: ' + Path(args[0]).name)
    return completed.stdout.strip()


def atomic_write(path, text):
    """Write text and rename it into place, so a crash keeps the previous file."""
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(6))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_json_state(path, missing, damaged, unsupported, limit=1024 * 1024, schema=1, error=RuntimeError):
    """Read a root-owned JSON state file, rejecting one that is missing, oversized or of an unknown schema."""
    try:
        if Path(path).stat().st_size > limit:
            raise error(damaged)
        state = json.loads(Path(path).read_text())
    except FileNotFoundError:
        raise error(missing) from None
    except ValueError:
        raise error(damaged) from None
    if state.get('schema') != schema:
        raise error(unsupported)
    return state
