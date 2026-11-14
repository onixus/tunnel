#!/usr/bin/env python3
"""Copy H UI and portal accounts into console.db. Sources stay read-only.

Prints counts and password fingerprints, never passwords. Refuses a source
that was already imported. Does not stop panels or switch authentication.
"""
import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server' / 'console'))
import panel_shadow


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--console-db', required=True, type=Path)
    parser.add_argument('--hui-db', type=Path)
    parser.add_argument('--portal-db', type=Path)
    args = parser.parse_args()
    if args.hui_db is None and args.portal_db is None:
        parser.error('Укажите --hui-db, --portal-db или оба')
    args.console_db.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    connection = sqlite3.connect(args.console_db)
    try:
        report = panel_shadow.import_panels(
            connection,
            hysteria=args.hui_db,
            portal=args.portal_db,
        )
    except panel_shadow.PanelImportError as error:
        print(str(error), file=sys.stderr)
        return 2
    finally:
        connection.close()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
