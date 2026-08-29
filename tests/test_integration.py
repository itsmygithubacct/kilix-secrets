#!/usr/bin/env python3
"""End-to-end F112 daemon, CLI, persistence, and descriptor tests."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time


class Checks:
    def __init__(self) -> None:
        self.total = 0
        self.failed = 0

    def check(self, condition: bool, message: str) -> None:
        self.total += 1
        if not condition:
            self.failed += 1
            print(f"FAIL integration: {message}", file=sys.stderr)


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
            input_value: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
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
                              timeout=30)
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    options = parser.parse_args()
    build_dir = Path(options.build_dir).resolve()
    daemon = build_dir / "kilix-secretsd"
    cli = build_dir / "kilix-secrets"
    consumer = Path(__file__).with_name("fd_consumer.py").resolve()
    scratch = Path(os.environ.get("TMPDIR", ""))
    checks = Checks()
    checks.check(scratch.is_absolute() and scratch.is_dir() and not scratch.is_symlink(),
                 "TMPDIR is an absolute, existing, non-symlink directory")
    root = Path(tempfile.mkdtemp(prefix="ksec-integration.", dir=scratch))
    runtime = root / "runtime"
    socket_path = runtime / "kilix-secrets" / "control.sock"
    data_dir = root / "data"
    runtime.mkdir(mode=0o700)
    process: subprocess.Popen[bytes] | None = None
    passphrase = bytearray(secrets.token_bytes(32))
    previous_passphrase = bytearray()
    record_secret = bytearray(secrets.token_bytes(47))
    recovery = bytearray()
    previous_recovery = bytearray()
    try:
        process = start_daemon(daemon, socket_path, data_dir)
        checks.check(process.poll() is None, "daemon remains running")
        checks.check(stat.S_IMODE((socket_path.parent).stat().st_mode) == 0o700,
                     "socket directory mode is 0700")
        checks.check(stat.S_IMODE(socket_path.stat().st_mode) == 0o600,
                     "socket mode is 0600")
        checks.check(stat.S_IMODE(data_dir.stat().st_mode) == 0o700,
                     "data directory mode is 0700")

        initialized, rendered_recovery = run_init(
            cli, socket_path, "kilix-secrets.test", bytes(passphrase))
        checks.check(initialized.returncode == 0,
                     "initialization succeeds through a dedicated input descriptor")
        recovery.extend(rendered_recovery)
        checks.check(len(recovery) == 64 and all(chr(byte) in "0123456789abcdef"
                                                 for byte in recovery),
                     "initialization returns one 64-byte recovery rendering")
        checks.check(bytes(passphrase) not in initialized.stdout + initialized.stderr,
                     "passphrase is absent from initialization output")
        checks.check(bytes(recovery) not in initialized.stdout + initialized.stderr,
                     "recovery is absent from ordinary stdout and stderr")

        previous_recovery.extend(recovery)
        retried_init, retried_recovery = run_init(
            cli, socket_path, "kilix-secrets.test", bytes(passphrase))
        checks.check(retried_init.returncode == 0 and len(retried_recovery) == 64,
                     "unconfirmed initialization can replace a lost recovery rendering")
        checks.check(retried_recovery != bytes(previous_recovery),
                     "recovery retry mints a fresh independent secret")
        recovery[:] = retried_recovery

        refused = run_cli(cli, socket_path, "kilix-secrets.test", ["unlock"],
                          bytes(passphrase))
        checks.check(refused.returncode != 0 and b"denied" in refused.stderr,
                     "passphrase unlock is refused until recovery proof")
        confirmed = run_cli(cli, socket_path, "kilix-secrets.test",
                            ["unlock", "--recovery"], bytes(recovery))
        checks.check(confirmed.returncode == 0,
                     "recovery re-entry confirms custody and unlocks")

        added = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["add", "--type", "opaque", "--label", "Synthetic integration",
             "--field", "value"], bytes(record_secret),
        )
        record_id = added.stdout.strip().decode("ascii", errors="ignore")
        checks.check(added.returncode == 0 and len(record_id) == 32
                     and all(character in "0123456789abcdef" for character in record_id),
                     "record creation returns one opaque 128-bit ID")

        listed = run_cli(cli, socket_path, "kilix-secrets.test", ["list"])
        checks.check(listed.returncode == 0 and record_id.encode() in listed.stdout,
                     "owner listing includes the new record")
        checks.check(bytes(record_secret) not in listed.stdout + listed.stderr,
                     "metadata listing contains no secret bytes")
        other_list = run_cli(cli, socket_path, "other-app", ["list"])
        checks.check(other_list.returncode == 0 and record_id.encode() not in other_list.stdout,
                     "another application cannot enumerate the record")

        expected_hash = hashlib.sha256(record_secret).hexdigest()
        consumed = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["run", record_id, "value", "--", sys.executable, str(consumer),
             expected_hash],
        )
        checks.check(consumed.returncode == 0 and consumed.stdout == b"consumer-ok\n",
                     "consumer receives the exact secret only on an inherited descriptor")
        denied = run_cli(
            cli, socket_path, "other-app",
            ["run", record_id, "value", "--", sys.executable, str(consumer),
             expected_hash],
        )
        checks.check(denied.returncode != 0 and b"denied" in denied.stderr,
                     "cross-application descriptor delivery is denied")

        doctor = run_cli(cli, socket_path, "kilix-secrets.test", ["doctor"])
        checks.check(doctor.returncode == 0 and b"recovery=confirmed" in doctor.stdout
                     and b"records=1/1024" in doctor.stdout,
                     "doctor reports confirmed recovery and a 1/1024 record count")
        locked = run_cli(cli, socket_path, "kilix-secrets.test", ["lock"])
        checks.check(locked.returncode == 0, "explicit lock succeeds")
        locked_list = run_cli(cli, socket_path, "kilix-secrets.test", ["list"])
        checks.check(locked_list.returncode != 0 and b"vault locked" in locked_list.stderr,
                     "locked vault refuses metadata operations")
        unlocked = run_cli(cli, socket_path, "kilix-secrets.test", ["unlock"],
                           bytes(passphrase))
        checks.check(unlocked.returncode == 0,
                     "confirmed vault unlocks with the passphrase slot")

        previous_passphrase.extend(passphrase)
        replacement_passphrase = secrets.token_bytes(32)
        changed = run_cli(cli, socket_path, "kilix-secrets.test", ["passwd"],
                          replacement_passphrase)
        checks.check(changed.returncode == 0,
                     "passphrase slot rotation succeeds while unlocked")
        passphrase[:] = replacement_passphrase
        locked_after_change = run_cli(cli, socket_path, "kilix-secrets.test", ["lock"])
        checks.check(locked_after_change.returncode == 0,
                     "passphrase rotation leaves explicit lock available")
        stop_daemon(process)
        process = None
        process = start_daemon(daemon, socket_path, data_dir)
        old_unlock = run_cli(cli, socket_path, "kilix-secrets.test", ["unlock"],
                             bytes(previous_passphrase))
        checks.check(old_unlock.returncode != 0
                     and b"authentication failure" in old_unlock.stderr,
                     "retired passphrase no longer unwraps the master key")
        stop_daemon(process)
        process = None
        process = start_daemon(daemon, socket_path, data_dir)
        changed_unlock = run_cli(cli, socket_path, "kilix-secrets.test", ["unlock"],
                                 bytes(passphrase))
        checks.check(changed_unlock.returncode == 0,
                     "replacement passphrase survives daemon restart")

        stop_daemon(process)
        process = None
        process = start_daemon(daemon, socket_path, data_dir)
        after_restart = run_cli(cli, socket_path, "kilix-secrets.test", ["list"])
        checks.check(after_restart.returncode != 0
                     and b"vault locked" in after_restart.stderr,
                     "daemon restart returns to the locked state")
        restart_unlock = run_cli(cli, socket_path, "kilix-secrets.test", ["unlock"],
                                 bytes(passphrase))
        checks.check(restart_unlock.returncode == 0,
                     "persistent header and journal unlock after restart")
        consumed_again = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["run", record_id, "value", "--", sys.executable, str(consumer),
             expected_hash],
        )
        checks.check(consumed_again.returncode == 0
                     and consumed_again.stdout == b"consumer-ok\n",
                     "record decrypts correctly after restart")

        audit_path = data_dir / "audit.log"
        with audit_path.open("r+b", buffering=0) as audit_file:
            audit_file.truncate(4 * 1024 * 1024)
        read_while_degraded = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["run", record_id, "value", "--", sys.executable, str(consumer),
             expected_hash],
        )
        checks.check(read_while_degraded.returncode == 0,
                     "already-authorized read proceeds when audit is full")
        degraded_doctor = run_cli(cli, socket_path, "kilix-secrets.test", ["doctor"])
        checks.check(degraded_doctor.returncode == 0
                     and b"audit=degraded" in degraded_doctor.stdout,
                     "doctor makes audit degradation visible")
        refused_compaction = run_cli(cli, socket_path, "kilix-secrets.test",
                                     ["compact"])
        checks.check(refused_compaction.returncode != 0
                     and b"audit unavailable" in refused_compaction.stderr,
                     "audit failure blocks a mutating compaction")
        lock_when_degraded = run_cli(cli, socket_path, "kilix-secrets.test", ["lock"])
        checks.check(lock_when_degraded.returncode == 0,
                     "audit failure never blocks explicit lock")
        stop_daemon(process)
        process = None
        process = start_daemon(daemon, socket_path, data_dir)
        checks.check((data_dir / "audit.log.1").stat().st_size == 4 * 1024 * 1024,
                     "restart rotates the bounded full audit as 1/1 retained file")
        post_rotation_unlock = run_cli(cli, socket_path, "kilix-secrets.test",
                                       ["unlock"], bytes(passphrase))
        checks.check(post_rotation_unlock.returncode == 0,
                     "audit rotation restores mutation availability")

        compacted = run_cli(cli, socket_path, "kilix-secrets.test", ["compact"])
        checks.check(compacted.returncode == 0, "journal compaction succeeds")
        deleted = run_cli(cli, socket_path, "kilix-secrets.test", ["delete", record_id])
        checks.check(deleted.returncode == 0, "record deletion succeeds")
        empty = run_cli(cli, socket_path, "kilix-secrets.test", ["list"])
        checks.check(empty.returncode == 0 and record_id.encode() not in empty.stdout,
                     "deleted record is absent from owner listing")

        audit = (data_dir / "audit.log").read_bytes()
        rotated_audit = (data_dir / "audit.log.1").read_bytes()
        vault = (data_dir / "vault.ksv").read_bytes()
        journal = (data_dir / "journal.ksj").read_bytes()
        checks.check(bytes(passphrase) not in audit + rotated_audit + vault + journal,
                     "passphrase is absent from audit and persistent files")
        checks.check(bytes(previous_passphrase)
                     not in audit + rotated_audit + vault + journal,
                     "retired passphrase is absent from audit and persistent files")
        checks.check(bytes(recovery) not in audit + rotated_audit + vault + journal,
                     "recovery secret is absent from audit and persistent files")
        checks.check(bytes(previous_recovery)
                     not in audit + rotated_audit + vault + journal,
                     "superseded recovery secret is absent from persistent files")
        checks.check(bytes(record_secret) not in audit + rotated_audit + vault + journal,
                     "record secret is absent from audit and persistent files")
        checks.check(b"Synthetic integration" not in journal,
                     "private record label is encrypted")
        all_audit = audit + rotated_audit
        checks.check(b"event=create" in all_audit and b"event=delete" in all_audit
                     and b"event=recovery" in all_audit,
                     "audit covers creation, deletion, and recovery confirmation")
        limits = Path(f"/proc/{process.pid}/limits").read_text(encoding="ascii")
        core_line = next((line for line in limits.splitlines()
                          if line.startswith("Max core file size")), "")
        checks.check(" 0 " in core_line,
                     "daemon process has a zero-byte core limit")
    finally:
        if process is not None:
            stop_daemon(process)
        passphrase[:] = b"\x00" * len(passphrase)
        previous_passphrase[:] = b"\x00" * len(previous_passphrase)
        record_secret[:] = b"\x00" * len(record_secret)
        recovery[:] = b"\x00" * len(recovery)
        previous_recovery[:] = b"\x00" * len(previous_recovery)
        resolved = root.resolve()
        required_parent = scratch.resolve()
        if resolved.parent == required_parent and resolved.name.startswith("ksec-integration."):
            shutil.rmtree(resolved)
        else:
            checks.check(False, "refused unsafe integration cleanup path")
    print(f"integration checks: {checks.total - checks.failed}/{checks.total} passed")
    return 0 if checks.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
