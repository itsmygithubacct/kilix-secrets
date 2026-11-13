#!/usr/bin/env python3
"""Sealed-dataset daemon, client, and descriptor tests. Private daemon only."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time


APP = "kilix-secrets.test"
OTHER = "other-app"
NAME = "ledger"
MARKER = b"KILIX-DATASET-MARKER-7f3a"
SENTINEL = b"UNTOUCHED-OUTPUT"
# Exact sealed lengths for owner "kilix-secrets.test" (19) and name "ledger" (6).
SEALED_0 = 134
SEALED_1 = 135
SEALED_1MIB = 1048965
SEALED_64MIB = 67126389
UNSEAL_MAX = 67126556


class Checks:
    def __init__(self) -> None:
        self.total = 0
        self.failed = 0

    def check(self, condition: bool, message: str) -> None:
        self.total += 1
        if not condition:
            self.failed += 1
            print(f"FAIL datasets: {message}", file=sys.stderr)


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
            environment: dict[str, str] | None = None,
            timeout: float = 60) -> subprocess.CompletedProcess[bytes]:
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
                              timeout=timeout, env=environment)
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
                                   pass_fds=(secret_fd, recovery_write), timeout=60)
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


def run_reset(cli: Path, socket_path: Path, app_id: str,
              confirmation: str,
              passphrase: bytes) -> tuple[subprocess.CompletedProcess[bytes], bytes]:
    secret_fd = secret_pipe(passphrase)
    recovery_read, recovery_write = os.pipe2(os.O_CLOEXEC)
    command = [str(cli), "--socket", str(socket_path), "--app", app_id,
               "reset", "--confirm", confirmation,
               "--secret-fd", str(secret_fd),
               "--recovery-fd", str(recovery_write)]
    try:
        completed = subprocess.run(command, check=False, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   pass_fds=(secret_fd, recovery_write), timeout=60)
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


def wipe(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def last_line(stdout: bytes) -> str:
    lines = [line for line in stdout.splitlines() if line]
    if not lines:
        return ""
    return lines[-1].decode("ascii", errors="replace")


def cli_says(completed: subprocess.CompletedProcess[bytes], text: str) -> bool:
    return f"kilix-secrets: {text}\n".encode() in completed.stderr


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def write_plaintext(path: Path, size: int) -> str:
    digest = hashlib.sha256()
    remaining = size
    pattern = MARKER + b"\n"
    with path.open("wb") as handle:
        if size == 1:
            handle.write(b"Q")
            digest.update(b"Q")
            return digest.hexdigest()
        while remaining:
            unit = pattern * (((min(remaining, 1024 * 1024) // len(pattern)) + 1))
            chunk = unit[:remaining]
            handle.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def sparse_file(path: Path, size: int) -> None:
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    try:
        os.ftruncate(fd, size)
    finally:
        os.close(fd)


def read_until(process: subprocess.Popen[bytes], token: bytes, timeout: float) -> bytes:
    collected = bytearray()
    assert process.stdout is not None
    descriptor = process.stdout.fileno()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if token in collected:
            return bytes(collected)
        remaining = deadline - time.monotonic()
        ready, _, _ = select.select([descriptor], [], [], min(0.5, remaining))
        if not ready:
            if process.poll() is not None:
                break
            continue
        chunk = os.read(descriptor, 4096)
        if not chunk:
            break
        collected.extend(chunk)
    return bytes(collected)


def remove_tree(root: Path | None, scratch: Path) -> None:
    if root is None or root.parent != scratch:
        return
    if not (root.name.startswith("ksec-datasets.")
            or root.name.startswith("ksec-datasets-fill.")):
        return
    shutil.rmtree(root)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    options = parser.parse_args()
    build_dir = Path(options.build_dir).resolve()
    daemon = build_dir / "kilix-secretsd"
    cli = build_dir / "kilix-secrets"
    helper = build_dir / "dataset-helper"
    scratch = Path(os.environ.get("TMPDIR", ""))
    checks = Checks()
    checks.check(scratch.is_absolute() and scratch.is_dir() and not scratch.is_symlink(),
                 "TMPDIR is an absolute, existing, non-symlink directory")
    root = Path(tempfile.mkdtemp(prefix="ksec-datasets.", dir=scratch))
    runtime = root / "runtime"
    socket_path = runtime / "kilix-secrets" / "control.sock"
    data_dir = root / "data"
    runtime.mkdir(mode=0o700)
    process: subprocess.Popen[bytes] | None = None
    fill_process: subprocess.Popen[bytes] | None = None
    fill_root: Path | None = None
    passphrase = bytearray(secrets.token_bytes(32))
    recovery = bytearray()
    backup_passphrase = bytearray(secrets.token_bytes(32))
    reset_passphrase = bytearray(secrets.token_bytes(32))
    reset_recovery = bytearray()
    seal_elapsed = 0.0

    def finish() -> int:
        passed = checks.total - checks.failed
        print(f"datasets checks: {passed}/{checks.total}")
        return 0 if checks.failed == 0 else 1

    def helper_run(args: list[str], timeout: float = 90) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run([str(helper), *args], check=False,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout)

    def create_key(label: str) -> str:
        completed = helper_run(["create", str(socket_path), APP, label])
        line = last_line(completed.stdout)
        if completed.returncode == 0 and line.startswith("OK ") and len(line) == 35:
            return line.split(" ", 1)[1]
        checks.check(False, f"create {label} returned {line!r} "
                            f"stderr={completed.stderr.decode('ascii', 'replace')!r}")
        return ""

    def expect_error(args: list[str], text: str, message: str,
                     output: Path | None = None, timeout: float = 90) -> None:
        if output is not None:
            output.write_bytes(SENTINEL)
        completed = helper_run(args, timeout=timeout)
        line = last_line(completed.stdout)
        untouched = output is None or output.read_bytes() == SENTINEL
        checks.check(line == f"ERROR {text}" and untouched,
                     f"{message}: line={line!r} untouched={untouched} "
                     f"stderr={completed.stderr.decode('ascii', 'replace')!r}")

    try:
        checks.check(len(str(socket_path)) < 108, "socket path fits the Unix address")
        process = start_daemon(daemon, socket_path, data_dir)
        initialized, rendered = run_init(cli, socket_path, APP, bytes(passphrase))
        recovery.extend(rendered)
        checks.check(initialized.returncode == 0 and len(recovery) == 64,
                     "initialization returns one 64-byte recovery rendering")
        confirmed = run_cli(cli, socket_path, APP, ["unlock", "--recovery"],
                            bytes(recovery))
        checks.check(confirmed.returncode == 0, "recovery proof unlocks the new vault")
        if confirmed.returncode != 0:
            return finish()

        record_id = create_key("primary")
        if len(record_id) != 32:
            return finish()
        shown = run_cli(cli, socket_path, APP, ["show", record_id])
        checks.check(shown.returncode == 0
                     and b"type=dataset-key" in shown.stdout
                     and b"field=dataset-key" in shown.stdout
                     and b"owner=" + APP.encode() in shown.stdout
                     and MARKER not in shown.stdout
                     and re.search(br"[0-9a-f]{64}", shown.stdout) is None,
                     "show reports the dataset key metadata and no key bytes")

        ordinary = run_cli(cli, socket_path, APP,
                           ["add", "--type", "opaque", "--label", "ordinary",
                            "--field", "value"], b"ordinary-secret")
        ordinary_id = ordinary.stdout.strip().decode("ascii", errors="replace")
        checks.check(ordinary.returncode == 0 and len(ordinary_id) == 32,
                     "an ordinary secret can sit beside a dataset key")

        rounds = [
            (0, 0, SEALED_0, "empty"),
            (1, 1, SEALED_1, "one-byte"),
            (1024 * 1024, 1000000, SEALED_1MIB, "one-mebibyte"),
            (64 * 1024 * 1024, 2**64 - 1, SEALED_64MIB, "sixty-four-mebibytes"),
        ]
        sealed_1 = root / "sealed-1"
        plain_1 = root / "plain-1"
        plain_64 = root / "plain-64"
        for size, revision, sealed_len, label in rounds:
            plain = root / f"plain-{label}"
            sealed = root / f"sealed-{label}"
            opened = root / f"opened-{label}"
            digest = write_plaintext(plain, size)
            sealed.write_bytes(b"")
            opened.write_bytes(b"")
            timeout = 300 if size >= 64 * 1024 * 1024 else 120
            started = time.monotonic()
            sealed_run = helper_run(
                ["seal", str(socket_path), APP, record_id, NAME, str(revision),
                 str(plain), str(sealed)], timeout=timeout)
            if size == 64 * 1024 * 1024:
                seal_elapsed = time.monotonic() - started
                plain_64 = plain
            if size == 1:
                plain_1 = plain
                sealed_1 = sealed
            seal_line = last_line(sealed_run.stdout)
            prefix = b""
            if sealed.exists():
                with sealed.open("rb") as handle:
                    prefix = handle.read(10)
            unsealed_run = helper_run(
                ["unseal", str(socket_path), APP, record_id, NAME,
                 str(sealed), str(opened)], timeout=timeout)
            unseal_line = last_line(unsealed_run.stdout)
            opened_digest = file_sha256(opened) if opened.exists() else ""
            checks.check(
                seal_line == "OK"
                and sealed.stat().st_size == sealed_len
                and prefix == b"KSDSET01\x00\x01"
                and unseal_line == f"OK {revision}"
                and opened.stat().st_size == size
                and opened_digest == digest,
                f"round trip {label}: seal={seal_line!r} "
                f"sealed_size={sealed.stat().st_size if sealed.exists() else -1} "
                f"prefix={prefix!r} unseal={unseal_line!r} "
                f"opened_size={opened.stat().st_size if opened.exists() else -1}")

        too_big = root / "plain-too-big"
        sparse_file(too_big, 64 * 1024 * 1024 + 1)
        expect_error(
            ["seal", str(socket_path), APP, record_id, NAME, "4",
             str(too_big), str(root / "sealed-too-big")],
            "limit exceeded", "64 MiB + 1 seal is limit exceeded",
            root / "sealed-too-big", timeout=180)
        sparse_file(root / "sealed-past-max", UNSEAL_MAX + 1)
        expect_error(
            ["unseal", str(socket_path), APP, record_id, NAME,
             str(root / "sealed-past-max"), str(root / "opened-past-max")],
            "limit exceeded", "sealed file past the maximum is limit exceeded",
            root / "opened-past-max", timeout=180)

        regular = root / "regular-hello"
        regular.write_bytes(b"hello")
        for operation in ("seal", "unseal"):
            for kind, text in (
                ("unsealed", "invalid input"),
                ("pipe", "invalid input"),
                ("regular", "invalid input"),
                ("missing", "protocol failure"),
                ("oversize", "limit exceeded"),
                ("unsealed-big", "invalid input"),
            ):
                args = ["raw", str(socket_path), APP, operation, record_id, NAME,
                        "0", kind]
                if kind == "regular":
                    args.append(str(regular))
                expect_error(args, text,
                             f"raw {operation} descriptor {kind}",
                             timeout=120)

        expect_error(
            ["seal", str(socket_path), APP, ordinary_id, NAME, "0",
             str(plain_1), str(root / "sealed-ordinary")],
            "invalid input", "an ordinary secret is not a dataset key",
            root / "sealed-ordinary")
        expect_error(
            ["seal", str(socket_path), OTHER, record_id, NAME, "0",
             str(plain_1), str(root / "sealed-other")],
            "denied", "another application's capability cannot seal",
            root / "sealed-other")
        expect_error(
            ["unseal", str(socket_path), OTHER, record_id, NAME,
             str(sealed_1), str(root / "opened-other")],
            "denied", "another application's capability cannot unseal",
            root / "opened-other")
        expect_error(
            ["seal-scoped", str(socket_path), APP, record_id, NAME, "0",
             str(plain_1), str(root / "sealed-scoped"), ordinary_id],
            "denied", "a capability scoped to another record cannot seal",
            root / "sealed-scoped")
        expect_error(
            ["unseal-scoped", str(socket_path), APP, record_id, NAME,
             str(sealed_1), str(root / "opened-scoped"), ordinary_id],
            "denied", "a capability scoped to another record cannot unseal",
            root / "opened-scoped")

        other_key = create_key("secondary")
        checks.check(len(other_key) == 32 and other_key != record_id,
                     "a second dataset key has its own id")
        if len(other_key) == 32:
            other_plain = root / "plain-other"
            other_sealed = root / "sealed-other-key"
            other_plain.write_bytes(b"Z")
            other_sealed.write_bytes(b"")
            other_seal = helper_run(
                ["seal", str(socket_path), APP, other_key, NAME, "9",
                 str(other_plain), str(other_sealed)])
            checks.check(last_line(other_seal.stdout) == "OK",
                         "the second key seals its own file")
            expect_error(
                ["unseal", str(socket_path), APP, record_id, "other-name",
                 str(sealed_1), str(root / "opened-wrong-name")],
                "identity generation conflict",
                "the wrong dataset name is an identity generation conflict",
                root / "opened-wrong-name")
            expect_error(
                ["unseal", str(socket_path), APP, record_id, NAME,
                 str(other_sealed), str(root / "opened-wrong-key")],
                "identity generation conflict",
                "another key's sealed file is an identity generation conflict",
                root / "opened-wrong-key")

        flipped = root / "sealed-flipped"
        flipped.write_bytes(sealed_1.read_bytes())
        blob = bytearray(flipped.read_bytes())
        blob[-1] ^= 0x01
        flipped.write_bytes(blob)
        expect_error(
            ["unseal", str(socket_path), APP, record_id, NAME,
             str(flipped), str(root / "opened-flipped")],
            "authentication failure",
            "one flipped ciphertext byte is an authentication failure",
            root / "opened-flipped")
        original = root / "opened-original"
        original.write_bytes(b"")
        original_run = helper_run(
            ["unseal", str(socket_path), APP, record_id, NAME,
             str(sealed_1), str(original)])
        checks.check(last_line(original_run.stdout) == "OK 1"
                     and original.read_bytes() == b"Q",
                     "the unflipped sealed file still unseals")

        got = run_cli(cli, socket_path, APP,
                      ["run", record_id, "dataset-key", "--", "/bin/true"])
        granted = run_cli(cli, socket_path, APP,
                          ["grant", record_id, OTHER, "--verbs", "use"])
        revoked = run_cli(cli, socket_path, APP, ["revoke", record_id, OTHER])
        checks.check(cli_says(got, "denied") and b"not found" not in got.stderr,
                     "GET of a dataset key is denied")
        checks.check(cli_says(granted, "denied") and b"not found" not in granted.stderr,
                     "GRANT of a dataset key is denied")
        checks.check(cli_says(revoked, "denied") and b"not found" not in revoked.stderr,
                     "REVOKE of a dataset key is denied")
        replaced = helper_run(["replace", str(socket_path), APP, record_id])
        checks.check(last_line(replaced.stdout) == "ERROR denied",
                     "REPLACE of a dataset key is denied")
        typed = run_cli(cli, socket_path, APP,
                        ["add", "--type", "dataset-key", "--label", "not-a-key",
                         "--field", "dataset-key"], b"A" * 32)
        checks.check(cli_says(typed, "invalid input"),
                     "PUT of type dataset-key is invalid input")
        put_type = helper_run(["put-type", str(socket_path), APP])
        checks.check(last_line(put_type.stdout) == "ERROR invalid input",
                     "a type-1 record typed dataset-key is invalid input")

        def still_unseals(message: str) -> None:
            output = root / "opened-still"
            output.write_bytes(b"")
            completed = helper_run(
                ["unseal", str(socket_path), APP, record_id, NAME,
                 str(sealed_1), str(output)])
            checks.check(last_line(completed.stdout) == "OK 1"
                         and output.read_bytes() == b"Q", message)

        compacted = run_cli(cli, socket_path, APP, ["compact"])
        checks.check(compacted.returncode == 0, "compaction succeeds")
        still_unseals("the sealed file unseals after compaction")
        rotated = run_rotate(cli, socket_path, APP, bytes(passphrase), bytes(recovery))
        checks.check(rotated.returncode == 0, "master rotation succeeds")
        still_unseals("the sealed file unseals after master rotation")
        backup_path = root / "vault.ksb"
        exported = run_cli(cli, socket_path, APP,
                           ["export", "--output", str(backup_path)],
                           bytes(backup_passphrase))
        checks.check(exported.returncode == 0 and backup_path.is_file(),
                     "encrypted export succeeds")
        imported = run_cli(cli, socket_path, APP,
                           ["import", "--input", str(backup_path)],
                           bytes(backup_passphrase))
        checks.check(imported.returncode == 0, "encrypted import succeeds")
        restored = run_cli(cli, socket_path, APP, ["unlock"], bytes(passphrase))
        checks.check(restored.returncode == 0, "passphrase unlocks the imported vault")
        still_unseals("the sealed file unseals after backup import")

        audit = (data_dir / "audit.log").read_bytes()
        record_token = f"record={record_id}".encode()
        checks.check(MARKER not in audit and b"ledger" not in audit
                     and record_token in audit
                     and b"event=dataset-create outcome=begin" in audit
                     and b"event=dataset-create outcome=ok" in audit
                     and b"event=seal outcome=begin" in audit
                     and b"event=seal outcome=ok" in audit
                     and b"event=unseal outcome=begin" in audit
                     and b"event=unseal outcome=ok" in audit,
                     "audit records dataset begin/ok metadata and no plaintext")

        before = run_cli(cli, socket_path, APP, ["list"])
        before_count = len([line for line in before.stdout.splitlines() if line])
        crash_out = root / "sealed-crash"
        crash_out.write_bytes(SENTINEL)
        assert process is not None
        daemon_pid = process.pid
        crash = subprocess.Popen(
            [str(helper), "seal", str(socket_path), APP, record_id, NAME, "5",
             str(plain_64), str(crash_out), "announce"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        seen = read_until(crash, b"SENDING\n", 180.0)
        killed = False
        if b"SENDING\n" in seen:
            delay = min(max(seal_elapsed * 0.45, 0.05), max(seal_elapsed - 0.05, 0.05))
            time.sleep(delay)
            os.kill(daemon_pid, signal.SIGKILL)
            process.wait(timeout=10)
            killed = True
        crash_code = crash.wait(timeout=180)
        crash_stdout = seen
        if crash.stdout is not None:
            crash_stdout += crash.stdout.read()
            crash.stdout.close()
        if crash.stderr is not None:
            crash.stderr.close()
        checks.check(killed, "the running daemon was SIGKILLed during the 64 MiB seal")
        checks.check(crash_code != 0 and crash_out.read_bytes() == SENTINEL,
                     f"the interrupted seal writes 0 bytes (exit {crash_code}, "
                     f"line {last_line(crash_stdout)!r})")
        if killed:
            if process.stderr is not None:
                process.stderr.close()
            process = None
            process = start_daemon(daemon, socket_path, data_dir)
            revived = run_cli(cli, socket_path, APP, ["unlock"], bytes(passphrase))
            checks.check(revived.returncode == 0, "the vault unlocks after the killed daemon restarts")
        revived_show = run_cli(cli, socket_path, APP, ["show", record_id])
        revived_list = run_cli(cli, socket_path, APP, ["list"])
        revived_count = len([line for line in revived_list.stdout.splitlines() if line])
        checks.check(revived_show.returncode == 0
                     and b"type=dataset-key" in revived_show.stdout
                     and revived_count == before_count
                     and record_id.encode() in revived_list.stdout,
                     "restart loads the same records")
        still_unseals("a previously sealed file unseals after the killed daemon restarts")

        deleted = run_cli(cli, socket_path, APP,
                          ["delete", record_id, "--confirm", record_id])
        checks.check(deleted.returncode == 0, "the dataset key can be deleted")
        expect_error(
            ["seal", str(socket_path), APP, record_id, NAME, "0",
             str(plain_1), str(root / "sealed-deleted")],
            "not found", "seal of a deleted key is not found",
            root / "sealed-deleted")
        expect_error(
            ["unseal", str(socket_path), APP, record_id, NAME,
             str(sealed_1), str(root / "opened-deleted")],
            "not found", "unseal of a deleted key is not found",
            root / "opened-deleted")

        locked = run_cli(cli, socket_path, APP, ["lock"])
        checks.check(locked.returncode == 0, "the vault locks")
        expect_error(["create", str(socket_path), APP, "while-locked"],
                     "vault locked", "create while locked is vault locked")
        expect_error(
            ["seal", str(socket_path), APP, record_id, NAME, "0",
             str(plain_1), str(root / "sealed-locked")],
            "vault locked", "seal while locked is vault locked",
            root / "sealed-locked")
        expect_error(
            ["unseal", str(socket_path), APP, record_id, NAME,
             str(sealed_1), str(root / "opened-locked")],
            "vault locked", "unseal while locked is vault locked",
            root / "opened-locked")
        relocked = run_cli(cli, socket_path, APP, ["unlock"], bytes(passphrase))
        checks.check(relocked.returncode == 0, "passphrase unlocks after the lock checks")

        reset_key = create_key("reset-target")
        reset_plain = root / "plain-reset"
        reset_sealed = root / "sealed-reset"
        reset_plain.write_bytes(b"R")
        reset_sealed.write_bytes(b"")
        if len(reset_key) == 32:
            reset_seal = helper_run(
                ["seal", str(socket_path), APP, reset_key, NAME, "8",
                 str(reset_plain), str(reset_sealed)])
            checks.check(last_line(reset_seal.stdout) == "OK",
                         "the key that reset will remove seals once")
        reset_result, rendered_reset = run_reset(
            cli, socket_path, APP, "RESET-VAULT-AND-LOSE-IDENTITY",
            bytes(reset_passphrase))
        reset_recovery.extend(rendered_reset)
        checks.check(reset_result.returncode == 0 and len(reset_recovery) == 64,
                     "destructive reset returns a new recovery rendering")
        reset_unlock = run_cli(cli, socket_path, APP, ["unlock", "--recovery"],
                               bytes(reset_recovery))
        checks.check(reset_unlock.returncode == 0,
                     "recovery proof unlocks the reset vault")
        if len(reset_key) == 32:
            expect_error(
                ["unseal", str(socket_path), APP, reset_key, NAME,
                 str(reset_sealed), str(root / "opened-reset")],
                "not found", "unseal after destructive reset is not found",
                root / "opened-reset")

        stop_daemon(process)
        process = None
        fill_root = Path(tempfile.mkdtemp(prefix="ksec-datasets-fill.", dir=scratch))
        fill_runtime = fill_root / "runtime"
        fill_socket = fill_runtime / "kilix-secrets" / "control.sock"
        fill_data = fill_root / "data"
        fill_runtime.mkdir(mode=0o700)
        fill_passphrase = bytearray(secrets.token_bytes(32))
        fill_recovery = bytearray()
        try:
            fill_process = start_daemon(daemon, fill_socket, fill_data)
            fill_init, fill_rendered = run_init(
                cli, fill_socket, APP, bytes(fill_passphrase))
            fill_recovery.extend(fill_rendered)
            fill_confirm = run_cli(cli, fill_socket, APP, ["unlock", "--recovery"],
                                   bytes(fill_recovery))
            checks.check(fill_init.returncode == 0 and fill_confirm.returncode == 0,
                         "the record-limit vault initializes and unlocks")
            filled = helper_run(["fill", str(fill_socket), APP], timeout=300)
            checks.check(last_line(filled.stdout) == "LIMIT 1024",
                         f"the 1025th dataset key is limit exceeded "
                         f"({last_line(filled.stdout)!r})")
            doctor = run_cli(cli, fill_socket, APP, ["doctor"])
            checks.check(b"records=1024/1024" in doctor.stdout,
                         "doctor reports 1024/1024 live records")
            listed = run_cli(cli, fill_socket, APP, ["list"])
            listed_lines = [line for line in listed.stdout.splitlines() if line]
            if not listed_lines:
                checks.check(False, "record list was empty at the 1024 limit")
            else:
                first = listed_lines[0].split(b"\t", 1)[0].decode("ascii")
                removed = run_cli(cli, fill_socket, APP,
                                  ["delete", first, "--confirm", first])
                checks.check(removed.returncode == 0 and len(first) == 32,
                             "one live record can be deleted at the limit")
            opened_slot = helper_run(["create", str(fill_socket), APP, "after-delete"])
            blocked = helper_run(["create", str(fill_socket), APP, "past-limit"])
            checks.check(last_line(opened_slot.stdout).startswith("OK ")
                         and last_line(blocked.stdout) == "ERROR limit exceeded",
                         "one create fits after a delete and the next is limit exceeded")
            stop_daemon(fill_process)
            fill_process = None
            fill_process = start_daemon(daemon, fill_socket, fill_data)
            fill_unlock = run_cli(cli, fill_socket, APP, ["unlock"],
                                  bytes(fill_passphrase))
            doctor_again = run_cli(cli, fill_socket, APP, ["doctor"])
            checks.check(fill_unlock.returncode == 0
                         and b"records=1024/1024" in doctor_again.stdout,
                         "1024 records survive a restart")
        finally:
            if fill_process is not None:
                stop_daemon(fill_process)
                fill_process = None
            wipe(fill_passphrase)
            wipe(fill_recovery)
            remove_tree(fill_root, scratch)
            fill_root = None
        return finish()
    finally:
        if process is not None and process.poll() is None:
            stop_daemon(process)
        elif process is not None and process.stderr is not None:
            process.stderr.close()
        if fill_process is not None:
            stop_daemon(fill_process)
        wipe(passphrase)
        wipe(recovery)
        wipe(backup_passphrase)
        wipe(reset_passphrase)
        wipe(reset_recovery)
        remove_tree(fill_root, scratch)
        remove_tree(root, scratch)
