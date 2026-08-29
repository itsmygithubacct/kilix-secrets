#!/usr/bin/env python3
"""Run the logind signal monitor against an isolated authenticated D-Bus."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    options = parser.parse_args()
    binary = Path(options.binary).resolve()
    scratch = Path(os.environ.get("TMPDIR", ""))
    if not scratch.is_absolute() or not scratch.is_dir() or scratch.is_symlink():
        print("TMPDIR must be an absolute existing non-symlink directory",
              file=sys.stderr)
        return 2
    daemon = subprocess.Popen(
        ["dbus-daemon", "--session", "--nofork", "--nopidfile",
         "--print-address=1"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env={**os.environ, "TMPDIR": str(scratch)},
    )
    try:
        if daemon.stdout is None:
            return 2
        address = daemon.stdout.readline().strip()
        if not address or daemon.poll() is not None:
            error = daemon.stderr.read() if daemon.stderr is not None else ""
            print(f"isolated dbus startup failed ({len(error)} stderr bytes)",
                  file=sys.stderr)
            return 2
        completed = subprocess.run([str(binary), address], check=False,
                                   timeout=20)
        return completed.returncode
    finally:
        if daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=5)
        if daemon.stdout is not None:
            daemon.stdout.close()
        if daemon.stderr is not None:
            daemon.stderr.close()


if __name__ == "__main__":
    raise SystemExit(main())
