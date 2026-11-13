#!/usr/bin/env python3
"""CLI verbs dataset-create, seal, unseal, replace, get, status, and add --raw."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import pty
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time


PASSPHRASE = b"correct-horse-battery-staple"
SECRET = b"ordinary-secret-value"
SECRET_RAW = b"raw-secret\r\n"
SECRET_STRIP = b"stripped-secret\r\n"
REPLACED = b"replaced-secret-value"
REPLACED_RAW = b"replaced-raw\r\n"
PLAINTEXT = b"PLAINTEXT-SENTINEL-4f9c\r\n"
EMPTY = b""
MISSING_ID = "00112233445566778899aabbccddeeff"
STATUS_NONE = b"initialized=no recovery_confirmed=no unlocked=no\n"
STATUS_UNCONFIRMED = b"initialized=yes recovery_confirmed=no unlocked=no\n"
STATUS_LOCKED = b"initialized=yes recovery_confirmed=yes unlocked=no\n"
STATUS_UNLOCKED = b"initialized=yes recovery_confirmed=yes unlocked=yes\n"
LOCKED_ERROR = b"kilix-secrets: vault locked\n"
TERMINAL_ERROR = b"kilix-secrets: refusing to write to a terminal\n"
USAGE_MARKERS = (
    b"dataset-create --label LABEL\n",
    b"seal RECORD --name NAME --revision N --input FILE|- --output FILE|-\n",
    b"unseal RECORD --name NAME --input FILE|- --output FILE|-\n",
    b"replace RECORD --field NAME [--secret-fd N] [--raw]\n",
    b"get RECORD FIELD (--output FILE | --output-fd N)\n",
    b"status\n",
    b"[--raw]\n",
)


class Checks:
    def __init__(self) -> None:
        self.total = 0
        self.failed = 0

    def check(self, condition: bool, message: str) -> None:
        self.total += 1
        if not condition:
            self.failed += 1
            print(f"FAIL cli-datasets: {message}", file=sys.stderr)


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
            stdin: bytes | None = None,
            secret: bytes | None = None,
            pass_fds: tuple[int, ...] = ()) -> subprocess.CompletedProcess[bytes]:
    descriptor = -1
    command = [str(cli), "--socket", str(socket_path), "--app", app_id, *arguments]
    forwarded = pass_fds
    if secret is not None:
        descriptor = secret_pipe(secret)
        command.extend(["--secret-fd", str(descriptor)])
        forwarded = (*pass_fds, descriptor)
    try:
        if stdin is None:
            return subprocess.run(
                command, check=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=forwarded, timeout=30,
            )
        return subprocess.run(
            command, check=False, input=stdin,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=forwarded, timeout=30,
        )
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


def record_id_of(stdout: bytes) -> str | None:
    if stdout.count(b"\n") != 1 or not stdout.endswith(b"\n"):
        return None
    text = stdout[:-1].decode("ascii", errors="strict")
    if len(text) != 32 or any(character not in "0123456789abcdef" for character in text):
        return None
    return text


def is_private_file(path: Path) -> bool:
    status = path.lstat()
    return stat.S_ISREG(status.st_mode) and stat.S_IMODE(status.st_mode) == 0o600


def read_pty(master: int) -> bytes:
    os.set_blocking(master, False)
    chunks: list[bytes] = []
    while True:
        try:
            chunk = os.read(master, 65536)
        except BlockingIOError:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def run_unseal_on_terminal(cli: Path, socket_path: Path, app_id: str,
                           arguments: list[str],
                           stdin: bytes) -> tuple[int, bytes, bytes]:
    master, slave = pty.openpty()
    try:
        completed = subprocess.run(
            [str(cli), "--socket", str(socket_path), "--app", app_id, *arguments],
            check=False, input=stdin, stdout=slave,
            stderr=subprocess.PIPE, timeout=30,
        )
        return completed.returncode, read_pty(master), completed.stderr
    finally:
        os.close(master)
        os.close(slave)


def run_get_on_terminal(cli: Path, socket_path: Path, app_id: str,
                        record_id: str, field: str) -> tuple[int, bytes, bytes]:
    master, slave = pty.openpty()
    try:
        completed = subprocess.run(
            [str(cli), "--socket", str(socket_path), "--app", app_id,
             "get", record_id, field, "--output-fd", str(slave)],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, pass_fds=(slave,), timeout=30,
        )
        return completed.returncode, read_pty(master), completed.stderr
    finally:
        os.close(master)
        os.close(slave)


def show_text(record_id: str, revision: int, field: str,
              label: str = "bank-login") -> bytes:
    return (
        f"id={record_id}\n"
        "owner=kilix-secrets.test\n"
        "type=password\n"
        f"label={label}\n"
        f"revision={revision}\n"
        "expires_at=0\n"
        "expired=no\n"
        "fields=1/8\n"
        f"field={field}\n"
        "grants=0/16\n"
    ).encode()


def assert_usage(checks: Checks, completed: subprocess.CompletedProcess[bytes],
                 message: str) -> None:
    checks.check(
        completed.returncode == 2 and completed.stdout == b""
        and completed.stderr.startswith(b"usage: kilix-secrets ")
        and all(marker in completed.stderr for marker in USAGE_MARKERS),
        message,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    options = parser.parse_args()
    build_dir = Path(options.build_dir).resolve()
    daemon = build_dir / "kilix-secretsd"
    cli = build_dir / "kilix-secrets"
    scratch = Path(os.environ.get("TMPDIR", ""))
    checks = Checks()
    checks.check(scratch.is_absolute() and scratch.is_dir() and not scratch.is_symlink(),
                 "TMPDIR is an absolute, existing, non-symlink directory")
    root = Path(tempfile.mkdtemp(prefix="c.", dir=scratch))
    runtime = root / "r"
    socket_path = runtime / "kilix-secrets" / "control.sock"
    data_dir = root / "d"
    runtime.mkdir(mode=0o700)
    checks.check(len(str(socket_path)) < 108, "test socket path fits the unix socket limit")
    app = "kilix-secrets.test"
    process: subprocess.Popen[bytes] | None = None
    try:
        process = start_daemon(daemon, socket_path, data_dir)
        checks.check(process.poll() is None, "daemon remains running")

        absent = run_cli(cli, socket_path, app, ["status"])
        checks.check(absent.returncode == 0 and absent.stdout == STATUS_NONE
                     and absent.stderr == b"",
                     "status before init is the three clear flags")

        assert_usage(checks, run_cli(cli, socket_path, app, ["frobnicate"]),
                     "unknown command is rejected with usage")
        assert_usage(checks, run_cli(cli, socket_path, app, ["dataset-create"]),
                     "dataset-create without --label is rejected with usage")
        assert_usage(checks, run_cli(cli, socket_path, app,
                                     ["dataset-create", "--label"]),
                     "dataset-create with a missing label value is rejected with usage")
        assert_usage(checks, run_cli(cli, socket_path, app,
                                     ["dataset-create", "--label", "books", "--label", "other"]),
                     "duplicate dataset-create options are rejected with usage")
        assert_usage(checks, run_cli(cli, socket_path, app, ["dataset-create", "--bogus", "x"]),
                     "unknown dataset-create option is rejected with usage")
        assert_usage(checks, run_cli(cli, socket_path, app, ["seal"]),
                     "seal without arguments is rejected with usage")
        assert_usage(checks, run_cli(cli, socket_path, app,
                                     ["seal", MISSING_ID, "--name", "ledger",
                                      "--input", "in", "--output", "out"]),
                     "seal without --revision is rejected with usage")
        assert_usage(checks, run_cli(cli, socket_path, app,
                                     ["unseal", MISSING_ID, "--name", "ledger",
                                      "--revision", "1", "--input", "in", "--output", "out"]),
                     "unseal rejects --revision with usage")
        assert_usage(checks, run_cli(cli, socket_path, app, ["status", "--extra"]),
                     "status rejects an unknown option with usage")
        assert_usage(checks, run_cli(cli, socket_path, app, ["get", MISSING_ID]),
                     "get without a field and output is rejected with usage")
        assert_usage(checks, run_cli(cli, socket_path, app,
                                     ["get", MISSING_ID, "secret", "--output", "-"]),
                     "get rejects stdout output with usage")
        assert_usage(checks, run_cli(cli, socket_path, app, ["replace", MISSING_ID]),
                     "replace without --field is rejected with usage")
        assert_usage(checks, run_cli(cli, socket_path, app,
                                     ["add", "--label", "x", "--field", "secret"]),
                     "add without --type is rejected with usage")
        assert_usage(checks, run_cli(cli, socket_path, app,
                                     ["add", "--type", "password", "--label", "x",
                                      "--field", "secret", "--raw", "--raw"]),
                     "duplicate add --raw is rejected with usage")
        bad_revision = run_cli(cli, socket_path, app,
                               ["seal", MISSING_ID, "--name", "ledger",
                                "--revision", "18446744073709551616",
                                "--input", "in", "--output", "out"])
        checks.check(bad_revision.returncode == 1 and bad_revision.stdout == b""
                     and bad_revision.stderr == b"kilix-secrets: invalid input\n",
                     "a revision above uint64 is invalid input")
        bad_id = run_cli(cli, socket_path, app,
                         ["seal", "ZZ", "--name", "ledger", "--revision", "1",
                          "--input", "in", "--output", "out"])
        checks.check(bad_id.returncode == 1 and bad_id.stdout == b""
                     and bad_id.stderr == b"kilix-secrets: invalid input\n",
                     "a non-hex record id is invalid input")

        initialized, recovery = run_init(cli, socket_path, app, PASSPHRASE)
        checks.check(initialized.returncode == 0 and len(recovery) == 64
                     and initialized.stdout == b"",
                     "init succeeds and renders a 64-character recovery secret")
        unconfirmed = run_cli(cli, socket_path, app, ["status"])
        checks.check(unconfirmed.returncode == 0 and unconfirmed.stdout == STATUS_UNCONFIRMED
                     and unconfirmed.stderr == b"",
                     "status after init is initialized, unconfirmed, and locked")

        locked_list = run_cli(cli, socket_path, app, ["list"])
        plain_path = root / "plain.bin"
        plain_path.write_bytes(PLAINTEXT)
        locked_out = root / "locked-seal.bin"
        locked_seal = run_cli(
            cli, socket_path, app,
            ["seal", MISSING_ID, "--name", "ledger", "--revision", "7",
             "--input", str(plain_path), "--output", str(locked_out)])
        checks.check(locked_list.returncode == locked_seal.returncode
                     and locked_list.returncode not in (0, 2)
                     and locked_list.stderr == LOCKED_ERROR
                     and locked_seal.stderr == LOCKED_ERROR
                     and locked_seal.stdout == b""
                     and not locked_out.exists(),
                     "a locked vault keeps the existing vault-locked exit and creates no output")

        confirmed = run_cli(cli, socket_path, app, ["unlock", "--recovery"],
                            secret=recovery)
        checks.check(confirmed.returncode == 0, "recovery confirmation unlocks")
        unlocked = run_cli(cli, socket_path, app, ["status"])
        checks.check(unlocked.returncode == 0 and unlocked.stdout == STATUS_UNLOCKED
                     and unlocked.stderr == b"",
                     "status while unlocked reports all three flags set")

        added = run_cli(cli, socket_path, app,
                        ["add", "--type", "password", "--label", "bank-login",
                         "--field", "secret"],
                        secret=SECRET)
        record_id = record_id_of(added.stdout)
        checks.check(added.returncode == 0 and added.stderr == b"" and record_id is not None,
                     "add prints exactly one 32-hex record id")
        if record_id is None:
            record_id = MISSING_ID
        shown = run_cli(cli, socket_path, app, ["show", record_id])
        checks.check(shown.returncode == 0 and shown.stdout == show_text(record_id, 1, "secret")
                     and shown.stderr == b"",
                     "show after add is revision 1 with the stored type, label, and expiry")
        got = root / "got-secret.bin"
        fetched = run_cli(cli, socket_path, app,
                          ["get", record_id, "secret", "--output", str(got)])
        checks.check(fetched.returncode == 0 and fetched.stdout == b"" and fetched.stderr == b""
                     and is_private_file(got) and got.read_bytes() == SECRET,
                     "get writes the exact secret to a new 0600 file")

        replaced = run_cli(cli, socket_path, app,
                           ["replace", record_id, "--field", "secret"],
                           secret=REPLACED)
        shown_replaced = run_cli(cli, socket_path, app, ["show", record_id])
        got_replaced = root / "got-replaced.bin"
        fetched_replaced = run_cli(
            cli, socket_path, app,
            ["get", record_id, "secret", "--output", str(got_replaced)])
        checks.check(replaced.returncode == 0 and replaced.stdout == b"" and replaced.stderr == b""
                     and shown_replaced.returncode == 0
                     and shown_replaced.stdout == show_text(record_id, 2, "secret")
                     and fetched_replaced.returncode == 0
                     and got_replaced.read_bytes() == REPLACED,
                     "replace keeps type, label, and expiry, bumps revision, and stores the field")

        raw_added = run_cli(cli, socket_path, app,
                            ["add", "--type", "password", "--label", "raw-login",
                             "--field", "secret", "--raw"],
                            secret=SECRET_RAW)
        raw_id = record_id_of(raw_added.stdout)
        checks.check(raw_added.returncode == 0 and raw_added.stderr == b""
                     and raw_id is not None,
                     "add --raw returns a record id")
        if raw_id is None:
            raw_id = MISSING_ID
        raw_got = root / "got-raw.bin"
        raw_fetch = run_cli(cli, socket_path, app,
                            ["get", raw_id, "secret", "--output", str(raw_got)])
        checks.check(raw_fetch.returncode == 0 and raw_got.read_bytes() == SECRET_RAW,
                     "add --raw keeps the trailing CR/LF byte-exact")
        raw_replaced = run_cli(cli, socket_path, app,
                               ["replace", raw_id, "--field", "token", "--raw"],
                               secret=REPLACED_RAW)
        raw_replaced_got = root / "got-raw-replaced.bin"
        raw_replaced_fetch = run_cli(
            cli, socket_path, app,
            ["get", raw_id, "token", "--output", str(raw_replaced_got)])
        raw_shown = run_cli(cli, socket_path, app, ["show", raw_id])
        checks.check(raw_replaced.returncode == 0 and raw_replaced.stdout == b""
                     and raw_replaced.stderr == b""
                     and raw_replaced_fetch.returncode == 0
                     and raw_replaced_got.read_bytes() == REPLACED_RAW
                     and raw_shown.returncode == 0
                     and raw_shown.stdout == show_text(raw_id, 4, "token", "raw-login"),
                     "replace --raw keeps CR/LF and the record type, label, and expiry")

        # A record with two fields can only come from the C API. The CLI writes
        # one field, so replacing such a record would drop the other one.
        two_value = root / "two-field-value.bin"
        two_value.write_bytes(b"two-field-secret")
        two_put = subprocess.run(
            [str(build_dir / "record-helper"), "put2", str(socket_path), str(two_value)],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30)
        two_id = record_id_of(two_put.stdout)
        checks.check(two_put.returncode == 0 and two_id is not None,
                     "record-helper put2 creates a two-field record")
        if two_id is None:
            two_id = MISSING_ID
        two_before = run_cli(cli, socket_path, app, ["show", two_id])
        two_replace = run_cli(cli, socket_path, app,
                              ["replace", two_id, "--field", "value"],
                              secret=REPLACED)
        two_after = run_cli(cli, socket_path, app, ["show", two_id])
        checks.check(two_before.returncode == 0 and b"fields=2/8\n" in two_before.stdout
                     and two_replace.returncode == 1 and two_replace.stdout == b""
                     and two_replace.stderr
                     == b"kilix-secrets: replace needs a record with exactly one field; "
                        b"this record has 2\nkilix-secrets: invalid input\n"
                     and two_after.returncode == 0
                     and two_after.stdout == two_before.stdout,
                     "replace refuses a two-field record and leaves it unchanged")

        stripped = run_cli(cli, socket_path, app,
                           ["add", "--type", "password", "--label", "stripped-login",
                            "--field", "secret"],
                           secret=SECRET_STRIP)
        stripped_id = record_id_of(stripped.stdout)
        checks.check(stripped.returncode == 0 and stripped.stderr == b""
                     and stripped_id is not None,
                     "add without --raw accepts a secret that ends in CR/LF")
        if stripped_id is None:
            stripped_id = MISSING_ID
        stripped_got = root / "got-stripped.bin"
        stripped_fetch = run_cli(
            cli, socket_path, app,
            ["get", stripped_id, "secret", "--output", str(stripped_got)])
        checks.check(stripped_fetch.returncode == 0
                     and stripped_got.read_bytes() == b"stripped-secret",
                     "add without --raw still strips trailing CR/LF")

        created = run_cli(cli, socket_path, app,
                          ["dataset-create", "--label", "books"])
        dataset_id = record_id_of(created.stdout)
        checks.check(created.returncode == 0 and created.stderr == b"" and dataset_id is not None,
                     "dataset-create prints exactly one 32-hex record id")
        if dataset_id is None:
            dataset_id = MISSING_ID
        sealed_path = root / "ledger.sealed"
        sealed = run_cli(cli, socket_path, app,
                         ["seal", dataset_id, "--name", "ledger", "--revision", "7",
                          "--input", str(plain_path), "--output", str(sealed_path)])
        checks.check(sealed.returncode == 0 and sealed.stdout == b"" and sealed.stderr == b""
                     and is_private_file(sealed_path) and sealed_path.stat().st_size > 0,
                     "seal creates a 0600 file and writes nothing else")
        unsealed_path = root / "ledger.plain"
        unsealed = run_cli(cli, socket_path, app,
                           ["unseal", dataset_id, "--name", "ledger",
                            "--input", str(sealed_path), "--output", str(unsealed_path)])
        checks.check(unsealed.returncode == 0 and unsealed.stdout == b""
                     and unsealed.stderr == b"revision=7\n"
                     and is_private_file(unsealed_path)
                     and unsealed_path.read_bytes() == PLAINTEXT,
                     "unseal writes the exact plaintext and revision=7 on stderr")

        streamed = run_cli(cli, socket_path, app,
                           ["seal", dataset_id, "--name", "ledger", "--revision", "7",
                            "--input", "-", "--output", "-"],
                           stdin=PLAINTEXT)
        checks.check(streamed.returncode == 0 and streamed.stderr == b""
                     and streamed.stdout != b"" and streamed.stdout != PLAINTEXT,
                     "seal from stdin to stdout returns only the sealed bytes")
        streamed_back = run_cli(cli, socket_path, app,
                                ["unseal", dataset_id, "--name", "ledger",
                                 "--input", "-", "--output", "-"],
                                stdin=streamed.stdout)
        checks.check(streamed_back.returncode == 0
                     and streamed_back.stdout == PLAINTEXT
                     and streamed_back.stderr == b"revision=7\n",
                     "unseal to a pipe prints the exact plaintext and revision")

        empty_sealed = run_cli(cli, socket_path, app,
                               ["seal", dataset_id, "--name", "empty-set",
                                "--revision", "0", "--input", "-", "--output", "-"],
                               stdin=EMPTY)
        empty_plain = root / "empty.plain"
        empty_back = run_cli(cli, socket_path, app,
                             ["unseal", dataset_id, "--name", "empty-set",
                              "--input", "-", "--output", str(empty_plain)],
                             stdin=empty_sealed.stdout)
        checks.check(empty_sealed.returncode == 0 and empty_back.returncode == 0
                     and empty_plain.read_bytes() == b""
                     and empty_back.stderr == b"revision=0\n"
                     and is_private_file(empty_plain),
                     "an empty plaintext seals at revision 0 and unseals byte-exact")

        max_revision = "18446744073709551615"
        max_sealed = root / "max.sealed"
        max_plain = root / "max.plain"
        max_seal = run_cli(cli, socket_path, app,
                           ["seal", dataset_id, "--name", "max-rev",
                            "--revision", max_revision, "--input", str(plain_path),
                            "--output", str(max_sealed)])
        max_unseal = run_cli(cli, socket_path, app,
                             ["unseal", dataset_id, "--name", "max-rev",
                              "--input", str(max_sealed), "--output", str(max_plain)])
        checks.check(max_seal.returncode == 0 and max_unseal.returncode == 0
                     and max_unseal.stderr == b"revision=18446744073709551615\n"
                     and max_plain.read_bytes() == PLAINTEXT,
                     "the largest revision round-trips and is printed in decimal")

        occupied = root / "occupied.sealed"
        occupied.write_bytes(b"KEEP-ME-INTACT\n")
        occupied.chmod(0o640)
        refused_exists = run_cli(
            cli, socket_path, app,
            ["seal", dataset_id, "--name", "ledger", "--revision", "7",
             "--input", str(plain_path), "--output", str(occupied)])
        checks.check(refused_exists.returncode != 0 and refused_exists.stdout == b""
                     and refused_exists.stderr == b"kilix-secrets: already exists\n"
                     and occupied.read_bytes() == b"KEEP-ME-INTACT\n"
                     and stat.S_IMODE(occupied.lstat().st_mode) == 0o640,
                     "an existing seal output is refused and left unchanged")
        occupied_plain = root / "occupied.plain"
        occupied_plain.write_bytes(b"KEEP-PLAIN\n")
        refused_plain = run_cli(
            cli, socket_path, app,
            ["unseal", dataset_id, "--name", "ledger",
             "--input", str(sealed_path), "--output", str(occupied_plain)])
        checks.check(refused_plain.returncode != 0
                     and refused_plain.stderr == b"kilix-secrets: already exists\n"
                     and occupied_plain.read_bytes() == b"KEEP-PLAIN\n",
                     "an existing unseal output is refused and left unchanged")
        occupied_get = root / "occupied-get.bin"
        occupied_get.write_bytes(b"KEEP-GET\n")
        refused_get = run_cli(cli, socket_path, app,
                              ["get", record_id, "secret", "--output", str(occupied_get)])
        checks.check(refused_get.returncode != 0
                     and refused_get.stderr == b"kilix-secrets: already exists\n"
                     and occupied_get.read_bytes() == b"KEEP-GET\n",
                     "an existing get output is refused and left unchanged")

        failed_seal = root / "failed-seal.bin"
        failed = run_cli(cli, socket_path, app,
                         ["seal", MISSING_ID, "--name", "ledger", "--revision", "7",
                          "--input", str(plain_path), "--output", str(failed_seal)])
        failed_stdout = run_cli(
            cli, socket_path, app,
            ["seal", MISSING_ID, "--name", "ledger", "--revision", "7",
             "--input", str(plain_path), "--output", "-"])
        checks.check(failed.returncode != 0 and not failed_seal.exists()
                     and failed_stdout.returncode != 0 and failed_stdout.stdout == b""
                     and b"revision=" not in failed_stdout.stderr
                     and PLAINTEXT not in failed_stdout.stdout + failed_stdout.stderr,
                     "a failed seal leaves no output file and writes nothing to stdout")
        failed_unseal = root / "failed-unseal.bin"
        bad_unseal = run_cli(
            cli, socket_path, app,
            ["unseal", dataset_id, "--name", "wrong-name",
             "--input", str(sealed_path), "--output", str(failed_unseal)])
        bad_unseal_stdout = run_cli(
            cli, socket_path, app,
            ["unseal", dataset_id, "--name", "wrong-name",
             "--input", str(sealed_path), "--output", "-"])
        checks.check(bad_unseal.returncode != 0 and not failed_unseal.exists()
                     and bad_unseal_stdout.returncode != 0
                     and bad_unseal_stdout.stdout == b""
                     and b"revision=" not in bad_unseal_stdout.stderr
                     and PLAINTEXT not in bad_unseal_stdout.stdout + bad_unseal_stdout.stderr,
                     "a failed unseal leaves no output file and writes nothing to stdout")
        failed_get = root / "failed-get.bin"
        missing_get = run_cli(cli, socket_path, app,
                              ["get", MISSING_ID, "secret", "--output", str(failed_get)])
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        try:
            missing_fd = run_cli(
                cli, socket_path, app,
                ["get", MISSING_ID, "secret", "--output-fd", str(write_fd)],
                pass_fds=(write_fd,))
        finally:
            os.close(write_fd)
        piped = os.read(read_fd, 64)
        os.close(read_fd)
        checks.check(missing_get.returncode != 0 and not failed_get.exists()
                     and missing_fd.returncode != 0 and missing_fd.stdout == b""
                     and piped == b"" and SECRET not in piped,
                     "a failed get leaves no output file and writes nothing to the descriptor")

        if sealed_path.is_file():
            term_code, term_out, term_err = run_unseal_on_terminal(
                cli, socket_path, app,
                ["unseal", dataset_id, "--name", "ledger",
                 "--input", "-", "--output", "-"],
                sealed_path.read_bytes())
        else:
            term_code, term_out, term_err = 1, PLAINTEXT, b""
        checks.check(term_code != 0 and term_err == TERMINAL_ERROR
                     and PLAINTEXT not in term_out and PLAINTEXT not in term_err,
                     "unseal --output - refuses a terminal and writes no plaintext")
        get_code, get_out, get_err = run_get_on_terminal(cli, socket_path, app,
                                                         record_id, "secret")
        checks.check(get_code != 0 and get_err == TERMINAL_ERROR
                     and REPLACED not in get_out and REPLACED not in get_err
                     and SECRET not in get_out,
                     "get refuses a terminal descriptor and writes no secret")

        locked = run_cli(cli, socket_path, app, ["lock"])
        locked_status = run_cli(cli, socket_path, app, ["status"])
        locked_list_again = run_cli(cli, socket_path, app, ["list"])
        locked_dataset = run_cli(cli, socket_path, app,
                                 ["dataset-create", "--label", "later"])
        checks.check(locked.returncode == 0
                     and locked_status.returncode == 0
                     and locked_status.stdout == STATUS_LOCKED
                     and locked_status.stderr == b""
                     and locked_dataset.returncode == locked_list_again.returncode
                     and locked_dataset.stderr == LOCKED_ERROR
                     and locked_dataset.stdout == b"",
                     "status works while locked and dataset-create keeps the locked exit code")
    finally:
        if process is not None:
            stop_daemon(process)
        resolved = root.resolve()
        required_parent = scratch.resolve()
        if resolved.parent == required_parent and resolved.name.startswith("c."):
            shutil.rmtree(resolved)
        else:
            checks.check(False, "refused unsafe cli-dataset cleanup path")
    print(f"cli dataset checks: {checks.total - checks.failed}/{checks.total} passed")
    return 0 if checks.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
