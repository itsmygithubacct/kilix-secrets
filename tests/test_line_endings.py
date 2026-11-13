#!/usr/bin/env python3
"""Binary-exact sensitive inputs: encoded records keep trailing CR/LF.

Passphrases and recovery secrets still have trailing line endings stripped.
Expected field bytes below are literals, not values produced by the code
under test.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time


PASSPHRASE = b"vault-passphrase"
BACKUP_PASSPHRASE = b"backup-passphrase"

# (label, put bytes, replace bytes). Each value is non-empty. The first four
# end in a line ending; the fifth contains every byte value, including CR/LF
# in the middle, and does not end in a line ending.
FIELD_CASES = (
    ("trailing-lf", b"alpha-secret\n", b"alpha-replaced\n"),
    ("trailing-crlf", b"beta-secret\r\n", b"beta-replaced\r\n"),
    ("trailing-cr", b"gamma-secret\r", b"gamma-replaced\r"),
    ("only-lf", b"\n", b"\n\n"),
    ("all-bytes", bytes(range(256)), bytes(range(255, -1, -1))),
)


class Checks:
    def __init__(self) -> None:
        self.total = 0
        self.failed = 0

    def check(self, condition: bool, message: str) -> None:
        self.total += 1
        if not condition:
            self.failed += 1
            print(f"FAIL line-endings: {message}", file=sys.stderr)


def secret_pipe(value: bytes) -> int:
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    try:
        offset = 0
        while offset < len(value):
            offset += os.write(write_fd, value[offset:])
    finally:
        os.close(write_fd)
    return read_fd


def run_cli(cli: Path, socket_path: Path, app_id: str, arguments: list[str],
            input_value: bytes | None = None,
            environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    descriptor = -1
    command = [str(cli), "--socket", str(socket_path), "--app", app_id, *arguments]
    pass_fds: tuple[int, ...] = ()
    if input_value is not None:
        descriptor = secret_pipe(input_value)
        command.extend(["--secret-fd", str(descriptor)])
        pass_fds = (descriptor,)
    try:
        return subprocess.run(command, check=False, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, pass_fds=pass_fds,
                              timeout=30, env=environment)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def run_init(cli: Path, socket_path: Path, app_id: str,
             passphrase: bytes) -> tuple[subprocess.CompletedProcess[bytes], bytes]:
    secret_fd = secret_pipe(passphrase)
    recovery_read, recovery_write = os.pipe2(os.O_CLOEXEC)
    command = [str(cli), "--socket", str(socket_path), "--app", app_id, "init",
               "--secret-fd", str(secret_fd), "--recovery-fd", str(recovery_write)]
    try:
        completed = subprocess.run(command, check=False, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   pass_fds=(secret_fd, recovery_write), timeout=30)
    finally:
        os.close(secret_fd)
        os.close(recovery_write)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(recovery_read, 256)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(recovery_read)
    return completed, b"".join(chunks).strip()


def run_rotate(cli: Path, socket_path: Path, app_id: str,
               passphrase: bytes, recovery: bytes) -> subprocess.CompletedProcess[bytes]:
    passphrase_fd = secret_pipe(passphrase)
    recovery_fd = secret_pipe(recovery)
    command = [str(cli), "--socket", str(socket_path), "--app", app_id,
               "rotate", "--passphrase-fd", str(passphrase_fd),
               "--recovery-fd", str(recovery_fd)]
    try:
        return subprocess.run(command, check=False, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              pass_fds=(passphrase_fd, recovery_fd), timeout=60)
    finally:
        os.close(passphrase_fd)
        os.close(recovery_fd)


def wait_for_socket(socket_path: Path, process: subprocess.Popen[bytes]) -> bool:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            status = socket_path.lstat()
        except FileNotFoundError:
            time.sleep(0.02)
            continue
        if stat.S_ISSOCK(status.st_mode):
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                probe.connect(str(socket_path))
                return True
            except (ConnectionRefusedError, FileNotFoundError):
                pass
            finally:
                probe.close()
        time.sleep(0.02)
    return False


def start_daemon(daemon: Path, socket_path: Path,
                 data_dir: Path) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [str(daemon), "--socket", str(socket_path), "--data-dir", str(data_dir),
         "--development-kdf-ops", "3", "--development-kdf-mem-mib", "256",
         "--idle-seconds", "60"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, close_fds=True,
    )
    if not wait_for_socket(socket_path, process):
        process.kill()
        process.wait(timeout=5)
        error = process.stderr.read() if process.stderr is not None else b""
        raise RuntimeError(f"daemon did not create socket (stderr bytes={len(error)})")
    return process


def stop_daemon(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=10)
    if process.stderr is not None:
        process.stderr.close()


def run_helper(helper: Path, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([str(helper), *arguments], check=False,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=30)


def short_output(completed: subprocess.CompletedProcess[bytes]) -> str:
    text = completed.stdout.decode("ascii", errors="replace").replace("\n", "\\n")
    error = completed.stderr.decode("ascii", errors="replace").replace("\n", "\\n")
    if len(text) > 80:
        text = text[:80] + "..."
    if len(error) > 100:
        error = error[:100] + "..."
    return f"exit={completed.returncode} stdout={text} stderr={error}"


def parse_record_id(stdout: bytes) -> str | None:
    try:
        text = stdout.strip().decode("ascii")
    except UnicodeDecodeError:
        return None
    if (len(text) == 32
            and all(character in "0123456789abcdef" for character in text)):
        return text
    return None


def write_secret(directory: Path, name: str, payload: bytes) -> Path:
    path = directory / name
    path.write_bytes(payload)
    path.chmod(0o600)
    return path


def mismatch_at(got: bytes | None, expected: bytes) -> str:
    if got is None:
        return "missing"
    if len(got) != len(expected):
        return f"length {len(got)}/{len(expected)}"
    for index, (left, right) in enumerate(zip(got, expected, strict=True)):
        if left != right:
            return f"byte {index} differs"
    return "equal"


def read_back(helper: Path, socket_path: Path, record_id: str,
              output: Path) -> tuple[subprocess.CompletedProcess[bytes], bytes | None]:
    if output.exists():
        output.unlink()
    completed = run_helper(helper, ["get", str(socket_path), record_id, str(output)])
    if completed.returncode != 0 or not output.is_file():
        return completed, None
    return completed, output.read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    options = parser.parse_args()
    build_dir = Path(options.build_dir).resolve()
    daemon = build_dir / "kilix-secretsd"
    cli = build_dir / "kilix-secrets"
    helper = build_dir / "record-helper"
    scratch = Path(os.environ.get("TMPDIR", ""))
    checks = Checks()
    checks.check(scratch.is_absolute() and scratch.is_dir()
                 and not scratch.is_symlink(),
                 "TMPDIR is an absolute, existing, non-symlink directory")
    root = Path(tempfile.mkdtemp(prefix="ksec-le.", dir=scratch))
    runtime = root / "runtime"
    socket_path = runtime / "kilix-secrets" / "control.sock"
    data_dir = root / "data"
    values = root / "values"
    reads = root / "reads"
    runtime.mkdir(mode=0o700)
    values.mkdir(mode=0o700)
    reads.mkdir(mode=0o700)
    process: subprocess.Popen[bytes] | None = None
    passphrase = bytearray(PASSPHRASE)
    backup_passphrase = bytearray(BACKUP_PASSPHRASE)
    recovery = bytearray()
    record_ids: dict[str, str] = {}
    replaced: dict[str, bytes] = {}
    try:
        process = start_daemon(daemon, socket_path, data_dir)
        checks.check(process.poll() is None, "daemon remains running")
        initialized, rendered_recovery = run_init(
            cli, socket_path, "kilix-secrets.test", bytes(passphrase))
        recovery.extend(rendered_recovery)
        confirmed = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["unlock", "--recovery"], bytes(recovery))
        checks.check(initialized.returncode == 0 and len(recovery) == 64
                     and confirmed.returncode == 0,
                     "fixture initializes with a passphrase that has no line ending "
                     "and confirms the 64-character recovery secret")
        if initialized.returncode != 0 or confirmed.returncode != 0:
            raise RuntimeError("line-ending fixture failed to initialize")

        for name, original, replacement in FIELD_CASES:
            original_path = write_secret(values, f"{name}-put.bin", original)
            replacement_path = write_secret(values, f"{name}-replace.bin", replacement)
            output_path = reads / f"{name}.bin"
            put = run_helper(helper, ["put", str(socket_path), str(original_path)])
            record_id = parse_record_id(put.stdout)
            checks.check(put.returncode == 0 and record_id is not None,
                         f"{name} put returns one 32-hex record id ({short_output(put)})")
            if record_id is None:
                checks.check(False, f"{name} put round-trip is missing")
                checks.check(False, f"{name} replace did not run")
                checks.check(False, f"{name} replace round-trip is missing")
                continue
            record_ids[name] = record_id
            _got_status, got = read_back(helper, socket_path, record_id, output_path)
            checks.check(got == original,
                         f"{name} put round-trip {mismatch_at(got, original)}")
            replaced_run = run_helper(
                helper, ["replace", str(socket_path), record_id, str(replacement_path)])
            checks.check(replaced_run.returncode == 0
                         and replaced_run.stdout.strip() == b"REPLACED",
                         f"{name} replace keeps the record ({short_output(replaced_run)})")
            _replaced_status, got_replaced = read_back(
                helper, socket_path, record_id, output_path)
            checks.check(got_replaced == replacement,
                         f"{name} replace round-trip {mismatch_at(got_replaced, replacement)}")
            if got_replaced == replacement:
                replaced[name] = replacement

        locked = run_cli(cli, socket_path, "kilix-secrets.test", ["lock"])
        unlocked_lf = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"],
            PASSPHRASE + b"\n")
        checks.check(locked.returncode == 0 and unlocked_lf.returncode == 0,
                     "a passphrase with a trailing LF still unlocks")
        locked_crlf = run_cli(cli, socket_path, "kilix-secrets.test", ["lock"])
        unlocked_crlf = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"],
            PASSPHRASE + b"\r\n")
        checks.check(locked_crlf.returncode == 0 and unlocked_crlf.returncode == 0,
                     "a passphrase with a trailing CRLF still unlocks")
        locked_cr = run_cli(cli, socket_path, "kilix-secrets.test", ["lock"])
        unlocked_cr = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"],
            PASSPHRASE + b"\r")
        checks.check(locked_cr.returncode == 0 and unlocked_cr.returncode == 0,
                     "a passphrase with a trailing CR still unlocks")

        rotated = run_rotate(
            cli, socket_path, "kilix-secrets.test",
            PASSPHRASE + b"\n", bytes(recovery) + b"\n")
        checks.check(rotated.returncode == 0,
                     "master rotation accepts a passphrase and recovery secret "
                     f"that end in LF ({short_output(rotated)})")
        sample_name = "all-bytes" if "all-bytes" in record_ids else "trailing-lf"
        sample_id = record_ids.get(sample_name)
        sample_expected = replaced.get(sample_name, b"")
        sample_got: bytes | None = None
        if sample_id is not None and rotated.returncode == 0:
            _sample_status, sample_got = read_back(
                helper, socket_path, sample_id, reads / "after-rotate.bin")
        checks.check(sample_id is not None and sample_got == sample_expected,
                     f"field {sample_name} remains "
                     f"{mismatch_at(sample_got, sample_expected)} after rotation")

        backup_path = root / "line-ending-backup.ksb"
        exported = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["export", "--output", str(backup_path)],
            BACKUP_PASSPHRASE + b"\n")
        backup_bytes = backup_path.read_bytes() if backup_path.is_file() else b""
        checks.check(exported.returncode == 0
                     and backup_bytes.startswith(b"KSVBAK01")
                     and b"beta-replaced\r\n" not in backup_bytes,
                     "export with a trailing-LF backup passphrase writes a "
                     "KSVBAK01 artifact that does not contain the field literal")
        imported = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["import", "--input", str(backup_path)],
            BACKUP_PASSPHRASE + b"\r\n")
        checks.check(imported.returncode == 0,
                     "import accepts a backup passphrase that ends in CRLF "
                     f"({short_output(imported)})")
        locked_after_import = None
        if sample_id is not None:
            locked_after_import = run_helper(
                helper, ["get", str(socket_path), sample_id,
                         str(reads / "while-locked.bin")])
        checks.check(locked_after_import is not None
                     and locked_after_import.returncode != 0,
                     "import leaves the vault locked")
        unlocked_after_import = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"],
            PASSPHRASE + b"\n")
        checks.check(unlocked_after_import.returncode == 0,
                     "the restored vault unlocks with a trailing-LF passphrase")
        for name, _original, replacement in FIELD_CASES:
            record_id = record_ids.get(name)
            if record_id is None:
                checks.check(False, f"{name} is absent after import")
                continue
            _status, got = read_back(
                helper, socket_path, record_id, reads / f"{name}-restored.bin")
            checks.check(got == replacement,
                         f"{name} survives backup import {mismatch_at(got, replacement)}")
    finally:
        if process is not None:
            stop_daemon(process)
        passphrase[:] = b"\x00" * len(passphrase)
        backup_passphrase[:] = b"\x00" * len(backup_passphrase)
        recovery[:] = b"\x00" * len(recovery)
        resolved = root.resolve()
        required_parent = scratch.resolve()
        if (resolved.parent == required_parent
                and resolved.name.startswith("ksec-le.")):
            shutil.rmtree(resolved)
        else:
            checks.check(False, "refused unsafe line-ending cleanup path")
    print(f"line-ending checks: {checks.total - checks.failed}/{checks.total} passed")
    return 0 if checks.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
