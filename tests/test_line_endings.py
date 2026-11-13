#!/usr/bin/env python3
"""Binary-exact sensitive inputs (no CR/LF stripping of encoded records). SKELETON: replaced by lane L5."""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    parser.parse_args()
    print("test_line_endings: PLACEHOLDER (lane L5)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
