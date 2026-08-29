#!/usr/bin/env python3
"""Staged install, uninstall, reinstall, linkage, and service-unit checks."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import shlex
import stat
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
            print(f"FAIL package: {message}", file=sys.stderr)


def snapshot(prefix: Path) -> dict[str, tuple[str, int, str]]:
    result: dict[str, tuple[str, int, str]] = {}
    if not prefix.exists():
        return result
    for path in sorted(prefix.rglob("*")):
        relative = path.relative_to(prefix).as_posix()
        status = path.lstat()
        if path.is_symlink():
            result[relative] = ("link", stat.S_IMODE(status.st_mode),
                                os.readlink(path))
        elif path.is_file():
            result[relative] = (
                "file", stat.S_IMODE(status.st_mode),
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
    return result


def run_make(source: Path, target: str, build: Path,
             stage: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["make", target, f"BUILD={build}", f"DESTDIR={stage}",
         "PREFIX=/usr/local"],
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
    root = Path(tempfile.mkdtemp(prefix="ksec-package.", dir=scratch))
    stage = root / "stage"
    prefix = stage / "usr/local"
    synthetic_vault = stage / "home/synthetic/.local/share/kilix-secrets"
    expected = {
        "bin/kilix-secrets", "bin/kilix-secretsd",
        "include/kilix_secrets.h", "lib/libkilix-secrets.a",
        "lib/libkilix-secrets.so", "lib/libkilix-secrets.so.0",
        "lib/pkgconfig/kilix-secrets.pc",
        "lib/systemd/user/kilix-secrets.service",
        "lib/systemd/user/kilix-secrets.socket",
        "share/doc/kilix-secrets/LICENSE",
        "share/doc/kilix-secrets/THIRD_PARTY_NOTICES.md",
        "share/doc/kilix-secrets/DEPENDENCIES.md",
        "share/doc/kilix-secrets/F113-CUSTODY-INTERFACE.md",
    }
    try:
        installed = run_make(source, "install", build, stage)
        first = snapshot(prefix)
        checks.check(installed.returncode == 0 and set(first) == expected,
                     "staged install produces the exact 13/13-file manifest")
        checks.check(first.get("lib/libkilix-secrets.so", ("", 0, ""))[0]
                     == "link"
                     and first["lib/libkilix-secrets.so"][2]
                     == "libkilix-secrets.so.0",
                     "shared-library development link is relative and exact")
        modes_ok = all(
            mode == (0o755 if name.startswith("bin/")
                     or name == "lib/libkilix-secrets.so.0" else 0o644)
            for name, (kind, mode, _) in first.items() if kind == "file"
        )
        checks.check(modes_ok, "all 12/12 installed regular-file modes are exact")

        needed_daemon = subprocess.run(
            ["readelf", "-d", str(prefix / "bin/kilix-secretsd")],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10,
        )
        needed_library = subprocess.run(
            ["readelf", "-d", str(prefix / "lib/libkilix-secrets.so.0")],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10,
        )
        checks.check(needed_daemon.returncode == 0
                     and b"libsodium.so.23" in needed_daemon.stdout
                     and b"libsystemd.so.0" in needed_daemon.stdout
                     and b"libsystemd.so.0" not in needed_library.stdout
                     and b"libsodium.so.23" in needed_library.stdout,
                     "ELF closure limits libsystemd to the daemon and libsodium to 2/2 consumers")

        installed_service = prefix / "lib/systemd/user/kilix-secrets.service"
        service_bytes = installed_service.read_bytes()
        checks.check(b"ExecStart=/usr/local/bin/kilix-secretsd --systemd "
                     b"--data-dir %h/.local/share/kilix-secrets"
                     in service_bytes
                     and b"ProtectSystem=strict" in service_bytes
                     and b"RestrictAddressFamilies=AF_UNIX" in service_bytes,
                     "installed service keeps the exact executable, storage, and sandbox contract")
        verification_units = root / "verify-units"
        verification_units.mkdir(mode=0o700)
        verification_service = verification_units / "kilix-secrets.service"
        verification_socket = verification_units / "kilix-secrets.socket"
        verification_service.write_bytes(service_bytes.replace(
            b"ExecStart=/usr/local/bin/kilix-secretsd --systemd",
            b"ExecStart=/bin/true --systemd",
        ))
        shutil.copyfile(prefix / "lib/systemd/user/kilix-secrets.socket",
                        verification_socket)
        verified = subprocess.run(
            ["systemd-analyze", "verify", str(verification_socket),
             str(verification_service)],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=20,
        )
        checks.check(verified.returncode == 0,
                     "socket/service syntax passes systemd verification with a test-only executable")

        fixture = root / "consumer.c"
        fixture.write_text(
            "#include <kilix_secrets.h>\n"
            "int main(void) {\n"
            "  unsigned char key[KSEC_IDENTITY_KEY_BYTES] = {0};\n"
            "  ksec_identity_info info = {0}; int lease = -1;\n"
            "  return ksec_result_string(KSEC_OK) == 0\n"
            "    || ksec_identity_open(0, 0, 0, key, &info, &lease)\n"
            "       != KSEC_ERR_INVALID\n"
            "    || ksec_identity_info_get(0, 0, 0, &info)\n"
            "       != KSEC_ERR_INVALID;\n"
            "}\n",
            encoding="ascii",
        )
        consumer = root / "consumer"
        consumer_cflags = shlex.split(os.environ.get("CFLAGS", ""))
        consumer_ldflags = shlex.split(os.environ.get("LDFLAGS", ""))
        compiled = subprocess.run(
            [os.environ.get("CC", "cc"), *consumer_cflags,
             "-std=c11", "-Wall", "-Wextra", "-Werror",
             f"-I{prefix / 'include'}", str(fixture),
             str(prefix / "lib/libkilix-secrets.a"),
             "/usr/lib/x86_64-linux-gnu/libsodium.so.23",
             *consumer_ldflags, "-o", str(consumer)],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30,
        )
        executed = subprocess.run([str(consumer)], check=False,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=10) \
            if compiled.returncode == 0 else None
        checks.check(compiled.returncode == 0 and executed is not None
                     and executed.returncode == 0,
                     "staged public header and static library build and run one identity-aware consumer")

        synthetic_vault.mkdir(parents=True, mode=0o700)
        vault_bytes = b"KSV-SYNTHETIC-ENCRYPTED-PRESERVATION-FIXTURE"
        vault_path = synthetic_vault / "vault.ksv"
        vault_path.write_bytes(vault_bytes)
        vault_path.chmod(0o600)
        uninstalled = run_make(source, "uninstall", build, stage)
        checks.check(uninstalled.returncode == 0 and snapshot(prefix) == {},
                     "uninstall removes 13/13 package files from the staged prefix")
        checks.check(vault_path.read_bytes() == vault_bytes,
                     "uninstall preserves the 1/1 synthetic user vault by default")

        reinstalled = run_make(source, "install", build, stage)
        second = snapshot(prefix)
        checks.check(reinstalled.returncode == 0 and second == first,
                     "reinstall reproduces the byte/mode/target manifest exactly")
        final_uninstall = run_make(source, "uninstall", build, stage)
        checks.check(final_uninstall.returncode == 0 and snapshot(prefix) == {}
                     and vault_path.read_bytes() == vault_bytes,
                     "second uninstall is idempotent for package files and vault custody")
    finally:
        resolved = root.resolve()
        required_parent = scratch.resolve()
        if (resolved.parent == required_parent
                and resolved.name.startswith("ksec-package.")):
            shutil.rmtree(resolved)
        else:
            checks.check(False, "refused unsafe package-test cleanup path")
    print(f"package lifecycle checks: {checks.total - checks.failed}/{checks.total} passed")
    return 0 if checks.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
