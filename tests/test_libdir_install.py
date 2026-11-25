#!/usr/bin/env python3
"""LIBDIR installs the libraries off $(PREFIX)/lib. The default layout stays.

`make install PREFIX=/usr/local` is the developer layout and is unchanged,
including the user unit's /usr/local executable path. A package passes LIBDIR
as the multiarch directory. The Debian rewrite of that unit lives in
debian/rules, not here, so this install must keep the developer path.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


class Checks:
    def __init__(self) -> None:
        self.total = 0
        self.failed = 0

    def check(self, condition: bool, message: str) -> None:
        self.total += 1
        if not condition:
            self.failed += 1
            print(f"FAIL libdir: {message}", file=sys.stderr)


def run_make(source: Path, target: str, build: Path, stage: Path,
             extra: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["make", target, f"BUILD={build}", f"DESTDIR={stage}", *extra],
        cwd=source, check=False, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=60,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    options = parser.parse_args()
    source = Path(__file__).resolve().parent.parent
    build = Path(options.build_dir).resolve()
    scratch = Path(os.environ.get("TMPDIR", ""))
    checks = Checks()
    checks.check(scratch.is_absolute() and scratch.is_dir()
                 and not scratch.is_symlink(),
                 "TMPDIR is an absolute existing non-symlink directory")
    multiarch = subprocess.run(
        ["dpkg-architecture", "-qDEB_HOST_MULTIARCH"],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=10,
    )
    checks.check(multiarch.returncode == 0 and multiarch.stdout.strip() != "",
                 "dpkg-architecture reports a multiarch tuple")
    triplet = multiarch.stdout.strip()
    root = Path(tempfile.mkdtemp(prefix="ksec-libdir.", dir=scratch))
    try:
        default_stage = root / "default"
        default = run_make(source, "install", build, default_stage,
                           ["PREFIX=/usr/local"])
        default_lib = (default_stage / "usr/local/lib/libkilix-secrets.so.0")
        default_pc = (default_stage
                      / "usr/local/lib/pkgconfig/kilix-secrets.pc")
        default_unit = (default_stage
                        / "usr/local/lib/systemd/user/kilix-secrets.service")
        checks.check(default.returncode == 0 and default_lib.is_file(),
                     "default install still places the shared library in lib/")
        default_pc_text = default_pc.read_bytes() if default_pc.is_file() else b""
        checks.check(b"prefix=/usr/local\n" in default_pc_text,
                     "default install writes prefix=/usr/local into pkg-config")
        checks.check(default.returncode == 0
                     and b"ExecStart=/usr/local/bin/kilix-secretsd --systemd "
                     b"--data-dir %h/.local/share/kilix-secrets"
                     in default_unit.read_bytes(),
                     "default install keeps the developer executable path")
        removed = run_make(source, "uninstall", build, default_stage,
                           ["PREFIX=/usr/local"])
        checks.check(removed.returncode == 0 and not default_lib.exists(),
                     "default uninstall removes the shared library")

        stage = root / "multi"
        libdir = f"/usr/lib/{triplet}"
        installed = run_make(
            source, "install", build, stage,
            ["PREFIX=/usr", f"LIBDIR={libdir}"],
        )
        library = stage / "usr/lib" / triplet / "libkilix-secrets.so.0"
        link = stage / "usr/lib" / triplet / "libkilix-secrets.so"
        static = stage / "usr/lib" / triplet / "libkilix-secrets.a"
        pc = stage / "usr/lib" / triplet / "pkgconfig/kilix-secrets.pc"
        flat = stage / "usr/lib/libkilix-secrets.so.0"
        daemon = stage / "usr/bin/kilix-secretsd"
        cli = stage / "usr/bin/kilix-secrets"
        unit = stage / "usr/lib/systemd/user/kilix-secrets.service"
        socket = stage / "usr/lib/systemd/user/kilix-secrets.socket"
        header = stage / "usr/include/kilix_secrets.h"
        checks.check(installed.returncode == 0 and library.is_file()
                     and not flat.exists(),
                     "LIBDIR receives the shared library and lib/ does not")
        checks.check(link.is_symlink() and os.readlink(link)
                     == "libkilix-secrets.so.0" and static.is_file()
                     and pc.is_file() and header.is_file(),
                     "LIBDIR also receives the development files")
        pc_text = pc.read_bytes() if pc.is_file() else b""
        checks.check(b"prefix=/usr\n" in pc_text
                     and b"libdir=${exec_prefix}/lib\n" in pc_text,
                     "LIBDIR install follows PREFIX and leaves libdir for packaging")
        checks.check(daemon.is_file() and cli.is_file() and unit.is_file()
                     and socket.is_file(),
                     "commands and user units stay on their prefix paths")
        checks.check(b"ExecStart=/usr/local/bin/kilix-secretsd" in unit.read_bytes(),
                     "LIBDIR install does not rewrite the user unit")
        gone = run_make(source, "uninstall", build, stage,
                        ["PREFIX=/usr", f"LIBDIR={libdir}"])
        checks.check(gone.returncode == 0 and not library.exists()
                     and not link.exists() and not daemon.exists()
                     and not unit.exists(),
                     "uninstall removes the LIBDIR payload and the commands")
    finally:
        resolved = root.resolve()
        if (resolved.parent == scratch.resolve()
                and resolved.name.startswith("ksec-libdir.")):
            shutil.rmtree(resolved)
        else:
            checks.check(False, "refused unsafe libdir-test cleanup path")
    print(f"libdir install checks: {checks.total - checks.failed}/{checks.total} passed")
    return 0 if checks.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
