#!/usr/bin/python3
"""Synthetic Kitty clipboard provider used only by the integration suite."""

from __future__ import annotations

import os
from pathlib import Path
import sys


def main() -> int:
    if sys.argv[1:3] != ["+kitten", "clipboard"]:
        return 2
    state_text = os.environ.get("KSEC_TEST_CLIPBOARD_FILE")
    if not state_text:
        return 2
    state = Path(state_text)
    if sys.argv[3:] == ["--get-clipboard"]:
        if state.exists():
            sys.stdout.buffer.write(state.read_bytes())
        return 0
    if sys.argv[3:] != ["--wait-for-completion"]:
        return 2
    value = sys.stdin.buffer.read()
    if value and os.environ.get("KSEC_TEST_CLIPBOARD_MUTATE") == "1":
        value = b"newer-synthetic-clipboard"
    state.write_bytes(value)
    state.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
