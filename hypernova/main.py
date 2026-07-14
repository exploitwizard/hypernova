#!/usr/bin/env python3
"""
main.py - Hypernova entry point.

Usage:
    hypernova [--db PATH]

Drops you into the interactive REPL described in repl.py.
"""

import argparse
import sys

from .repl import Shell


def main():
    parser = argparse.ArgumentParser(prog="hypernova",
                                      description="CLI-based, fully interactive HTTP brute-forcer")
    parser.add_argument("--db", help="Path to the SQLite database file "
                                      "(default: ~/.hypernova/hypernova.db)")
    args = parser.parse_args()

    shell = Shell(db_path=args.db)
    try:
        shell.run()
    except SystemExit:
        sys.exit(0)


if __name__ == "__main__":
    main()
