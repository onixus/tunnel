#!/usr/bin/env python3
"""Vendor the same APEX source into independently packaged static roots."""
import argparse
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'server/design-system'
TARGETS = [ROOT / path / 'apex' for path in (
    'server/console/static', 'server/upstream/app/static', 'server/overlay/app/static')]


def sync(check=False):
    files = {p.relative_to(SOURCE): p.read_bytes() for p in SOURCE.rglob('*') if p.is_file() and p.name != 'README.md'}
    for target in TARGETS:
        if check:
            actual = {p.relative_to(target): p.read_bytes() for p in target.rglob('*') if p.is_file()}
            if actual != files:
                raise SystemExit(f'{target.relative_to(ROOT)} differs; run python scripts/sync-design-system.py')
        else:
            if target.exists():
                shutil.rmtree(target)
            for name, content in files.items():
                dest = target / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    sync(parser.parse_args().check)
