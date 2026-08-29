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
                              pass_fds=(passphrase_fd, recovery_fd), timeout=30)
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
    fake_kitty_source = Path(__file__).with_name("fake_kitty.py").resolve()
    scratch = Path(os.environ.get("TMPDIR", ""))
    checks = Checks()
    checks.check(scratch.is_absolute() and scratch.is_dir() and not scratch.is_symlink(),
                 "TMPDIR is an absolute, existing, non-symlink directory")
    root = Path(tempfile.mkdtemp(prefix="ksec-integration.", dir=scratch))
    runtime = root / "runtime"
    socket_path = runtime / "kilix-secrets" / "control.sock"
    data_dir = root / "data"
    runtime.mkdir(mode=0o700)
    fake_bin = root / "fake-bin"
    fake_bin.mkdir(mode=0o700)
    fake_kitty = fake_bin / "kitty"
    shutil.copyfile(fake_kitty_source, fake_kitty)
    fake_kitty.chmod(0o700)
    clipboard_file = root / "synthetic-clipboard"
    clipboard_environment = os.environ.copy()
    clipboard_environment["PATH"] = f"{fake_bin}{os.pathsep}{clipboard_environment.get('PATH', '')}"
    clipboard_environment["KSEC_TEST_CLIPBOARD_FILE"] = str(clipboard_file)
    process: subprocess.Popen[bytes] | None = None
    passphrase = bytearray(secrets.token_bytes(32))
    previous_passphrase = bytearray()
    record_secret = bytearray(secrets.token_bytes(47))
    backup_passphrase = bytearray(secrets.token_bytes(32))
    recovery = bytearray()
    previous_recovery = bytearray()
    reset_recovery = bytearray()
    pre_reset_passphrase = bytearray()
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
        shown = run_cli(cli, socket_path, "kilix-secrets.test",
                        ["show", record_id])
        checks.check(shown.returncode == 0
                     and b"owner=kilix-secrets.test" in shown.stdout
                     and b"field=value" in shown.stdout
                     and b"grants=0/16" in shown.stdout
                     and bytes(record_secret) not in shown.stdout + shown.stderr,
                     "metadata-only show reports 0/16 grants and no secret value")

        expected_hash = hashlib.sha256(record_secret).hexdigest()
        consumed = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["run", record_id, "value", "--", sys.executable, str(consumer),
             expected_hash],
        )
        checks.check(consumed.returncode == 0 and consumed.stdout == b"consumer-ok\n",
                     "consumer receives the exact secret only on an inherited descriptor")
        copied = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["copy", record_id, "value", "--clear-seconds", "0"],
            environment=clipboard_environment,
        )
        checks.check(copied.returncode == 0 and clipboard_file.read_bytes() == b""
                     and b"not guaranteed" in copied.stderr
                     and b"clear attempted" in copied.stderr.lower()
                     and bytes(record_secret) not in copied.stdout + copied.stderr,
                     "clipboard copy warns and clears only the matching 1/1 value")
        changed_environment = clipboard_environment.copy()
        changed_environment["KSEC_TEST_CLIPBOARD_MUTATE"] = "1"
        changed_clipboard = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["copy", record_id, "value", "--clear-seconds", "0"],
            environment=changed_environment,
        )
        checks.check(changed_clipboard.returncode == 0
                     and clipboard_file.read_bytes()
                         == b"newer-synthetic-clipboard"
                     and b"left intact" in changed_clipboard.stderr,
                     "clipboard clear preserves 1/1 newer nonmatching values")
        denied = run_cli(
            cli, socket_path, "other-app",
            ["run", record_id, "value", "--", sys.executable, str(consumer),
             expected_hash],
        )
        checks.check(denied.returncode != 0 and b"denied" in denied.stderr,
                     "cross-application descriptor delivery is denied")

        granted = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["grant", record_id, "other-app", "--verbs",
             "read,use,replace,list-own"],
        )
        checks.check(granted.returncode == 0,
                     "owner creates one explicit cross-application grant")
        granted_list = run_cli(cli, socket_path, "other-app", ["list"])
        granted_show = run_cli(cli, socket_path, "other-app",
                               ["show", record_id])
        checks.check(granted_list.returncode == 0
                     and record_id.encode() in granted_list.stdout
                     and granted_show.returncode == 0
                     and b"grant=other-app\tverbs=read,replace,list-own,use"
                         in granted_show.stdout
                     and bytes(record_secret)
                         not in granted_show.stdout + granted_show.stderr,
                     "grantee can inspect authorized metadata but 0/1 secret values")
        granted_use = run_cli(
            cli, socket_path, "other-app",
            ["run", record_id, "value", "--", sys.executable, str(consumer),
             expected_hash],
        )
        checks.check(granted_use.returncode == 0
                     and granted_use.stdout == b"consumer-ok\n",
                     "explicit use grant authorizes exact descriptor delivery")
        denied_regrant = run_cli(
            cli, socket_path, "other-app",
            ["grant", record_id, "third-app", "--verbs", "read"],
        )
        checks.check(denied_regrant.returncode != 0
                     and b"denied" in denied_regrant.stderr,
                     "replace grantee cannot create or widen record grants")
        narrowed = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["grant", record_id, "other-app", "--verbs",
             "replace,list-own"],
        )
        narrowed_use = run_cli(
            cli, socket_path, "other-app",
            ["run", record_id, "value", "--", sys.executable, str(consumer),
             expected_hash],
        )
        checks.check(narrowed.returncode == 0 and narrowed_use.returncode != 0
                     and b"denied" in narrowed_use.stderr,
                     "grant narrowing takes effect on the next authorization")
        regranted = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["grant", record_id, "other-app", "--verbs",
             "read,use,replace,list-own"],
        )
        checks.check(regranted.returncode == 0,
                     "owner restores the explicit pilot-consumer grant")

        doctor = run_cli(cli, socket_path, "kilix-secrets.test", ["doctor"])
        checks.check(doctor.returncode == 0 and b"recovery=confirmed" in doctor.stdout
                     and b"records=1/1024" in doctor.stdout
                     and b"session_monitor=active" in doctor.stdout
                     and b"/64\n" in doctor.stdout,
                     "doctor reports recovery, 1/1024 records, and the logind monitor")
        process.send_signal(signal.SIGUSR1)
        signal_locked = run_cli(cli, socket_path, "kilix-secrets.test", ["list"])
        checks.check(signal_locked.returncode != 0
                     and b"vault locked" in signal_locked.stderr
                     and process.poll() is None,
                     "global lock signal clears custody while the daemon remains active")
        signal_unlocked = run_cli(cli, socket_path, "kilix-secrets.test",
                                  ["unlock"], bytes(passphrase))
        checks.check(signal_unlocked.returncode == 0,
                     "explicit unlock is required after the global lock input")
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

        active_dir = data_dir / "vault-current"
        pre_rotation_header = (active_dir / "vault.ksv").read_bytes()
        pre_rotation_journal = (active_dir / "journal.ksj").read_bytes()
        rotated = run_rotate(cli, socket_path, "kilix-secrets.test",
                             bytes(passphrase), bytes(recovery))
        checks.check(rotated.returncode == 0
                     and b"prior encrypted generation is retained" in rotated.stderr,
                     "master-key rotation commits through the dual-secret operation")
        post_rotation_header = (active_dir / "vault.ksv").read_bytes()
        post_rotation_journal = (active_dir / "journal.ksj").read_bytes()
        checks.check(post_rotation_header != pre_rotation_header
                     and post_rotation_journal != pre_rotation_journal,
                     "master rotation replaces both authenticated generation members")
        retained_generations = list(data_dir.glob(".vault-previous-*"))
        checks.check(len(retained_generations) == 1,
                     "master rotation retains exactly 1/1 prior encrypted generation")
        checks.check(len(retained_generations) == 1
                     and (retained_generations[0] / "vault.ksv").read_bytes()
                         == pre_rotation_header
                     and (retained_generations[0] / "journal.ksj").read_bytes()
                         == pre_rotation_journal,
                     "retained generation is the byte-exact pre-rotation pair")
        consumed_after_rotation = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["run", record_id, "value", "--", sys.executable, str(consumer),
             expected_hash],
        )
        checks.check(consumed_after_rotation.returncode == 0
                     and consumed_after_rotation.stdout == b"consumer-ok\n",
                     "rotated generation remains available through fresh capability custody")
        rotation_lock = run_cli(cli, socket_path, "kilix-secrets.test", ["lock"])
        rotation_passphrase_unlock = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"], bytes(passphrase))
        checks.check(rotation_lock.returncode == 0
                     and rotation_passphrase_unlock.returncode == 0,
                     "rotated passphrase slot unlocks the new master key")
        second_rotation_lock = run_cli(
            cli, socket_path, "kilix-secrets.test", ["lock"])
        rotation_recovery_unlock = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock", "--recovery"],
            bytes(recovery))
        checks.check(second_rotation_lock.returncode == 0
                     and rotation_recovery_unlock.returncode == 0,
                     "rotated recovery slot unlocks the same new generation")

        backup_path = root / "synthetic-encrypted-backup.ksb"
        exported = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["export", "--output", str(backup_path)], bytes(backup_passphrase),
        )
        backup_bytes = backup_path.read_bytes() if backup_path.exists() else b""
        checks.check(exported.returncode == 0 and backup_bytes.startswith(b"KSVBAK01")
                     and stat.S_IMODE(backup_path.stat().st_mode) == 0o600,
                     "encrypted export creates 1/1 bounded 0600 backup artifact")
        checks.check(bytes(record_secret) not in backup_bytes
                     and bytes(passphrase) not in backup_bytes
                     and bytes(recovery) not in backup_bytes,
                     "backup artifact contains no raw record, slot, or recovery secret")
        duplicate_export = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["export", "--output", str(backup_path)], bytes(backup_passphrase),
        )
        checks.check(duplicate_export.returncode != 0
                     and b"already exists" in duplicate_export.stderr
                     and backup_path.read_bytes() == backup_bytes,
                     "export refuses to overwrite the existing 1/1 backup")

        current_before_bad_import = (
            (active_dir / "vault.ksv").read_bytes(),
            (active_dir / "journal.ksj").read_bytes(),
        )
        wrong_backup_passphrase = secrets.token_bytes(32)
        wrong_import = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["import", "--input", str(backup_path)], wrong_backup_passphrase,
        )
        checks.check(wrong_import.returncode != 0
                     and b"authentication failure" in wrong_import.stderr
                     and current_before_bad_import == (
                         (active_dir / "vault.ksv").read_bytes(),
                         (active_dir / "journal.ksj").read_bytes(),
                     ), "wrong backup passphrase mutates 0/2 active generation members")
        corrupt_backup_path = root / "synthetic-corrupt-backup.ksb"
        corrupt_backup = bytearray(backup_bytes)
        corrupt_backup[-1] ^= 1
        corrupt_backup_path.write_bytes(corrupt_backup)
        corrupt_backup_path.chmod(0o600)
        corrupt_import = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["import", "--input", str(corrupt_backup_path)],
            bytes(backup_passphrase),
        )
        checks.check(corrupt_import.returncode != 0
                     and b"authentication failure" in corrupt_import.stderr
                     and current_before_bad_import == (
                         (active_dir / "vault.ksv").read_bytes(),
                         (active_dir / "journal.ksj").read_bytes(),
                     ), "corrupt backup mutates 0/2 active generation members")

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
        blocked_backup_path = root / "audit-blocked-backup.ksb"
        refused_export = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["export", "--output", str(blocked_backup_path)],
            bytes(backup_passphrase),
        )
        checks.check(refused_export.returncode != 0
                     and b"audit unavailable" in refused_export.stderr
                     and not blocked_backup_path.exists(),
                     "audit failure blocks export and leaves 0/1 partial artifacts")
        refused_import = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["import", "--input", str(backup_path)], bytes(backup_passphrase),
        )
        checks.check(refused_import.returncode != 0
                     and b"audit unavailable" in refused_import.stderr
                     and current_before_bad_import == (
                         (active_dir / "vault.ksv").read_bytes(),
                         (active_dir / "journal.ksj").read_bytes(),
                     ), "audit failure blocks import before 0/2 generation mutations")
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
        unconfirmed_delete = run_cli(
            cli, socket_path, "kilix-secrets.test", ["delete", record_id])
        wrong_confirmation = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["delete", record_id, "--confirm", "00" * 16],
        )
        still_present = run_cli(
            cli, socket_path, "kilix-secrets.test", ["list"])
        checks.check(unconfirmed_delete.returncode != 0
                     and wrong_confirmation.returncode != 0
                     and record_id.encode() in still_present.stdout,
                     "record deletion refuses 2/2 absent or mismatched confirmations")
        deleted = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["delete", record_id, "--confirm", record_id],
        )
        checks.check(deleted.returncode == 0, "record deletion succeeds")
        empty = run_cli(cli, socket_path, "kilix-secrets.test", ["list"])
        checks.check(empty.returncode == 0 and record_id.encode() not in empty.stdout,
                     "deleted record is absent from owner listing")

        restored = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["import", "--input", str(backup_path)], bytes(backup_passphrase),
        )
        checks.check(restored.returncode == 0
                     and b"explicit rollback" in restored.stderr,
                     "authenticated restore completes with the portable rollback limit")
        retained_after_restore = list(data_dir.glob(".vault-previous-*"))
        checks.check(len(retained_after_restore) == 2,
                     "restore retains exactly 2/2 displaced encrypted generations")
        list_after_restore = run_cli(
            cli, socket_path, "kilix-secrets.test", ["list"])
        checks.check(list_after_restore.returncode != 0
                     and b"vault locked" in list_after_restore.stderr,
                     "successful restore globally locks the vault")
        restore_unlock = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"], bytes(passphrase))
        restored_record = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["run", record_id, "value", "--", sys.executable, str(consumer),
             expected_hash],
        )
        checks.check(restore_unlock.returncode == 0
                     and restored_record.returncode == 0
                     and restored_record.stdout == b"consumer-ok\n",
                     "restored passphrase slot and 1/1 backed-up record agree")
        restored_grantee = run_cli(
            cli, socket_path, "other-app",
            ["run", record_id, "value", "--", sys.executable, str(consumer),
             expected_hash],
        )
        checks.check(restored_grantee.returncode == 0
                     and restored_grantee.stdout == b"consumer-ok\n",
                     "rotation and encrypted restore preserve the 1/1 grant")
        revoked = run_cli(cli, socket_path, "kilix-secrets.test",
                          ["revoke", record_id, "other-app"])
        revoked_use = run_cli(
            cli, socket_path, "other-app",
            ["run", record_id, "value", "--", sys.executable, str(consumer),
             expected_hash],
        )
        revoked_list = run_cli(cli, socket_path, "other-app", ["list"])
        checks.check(revoked.returncode == 0
                     and revoked_use.returncode != 0
                     and b"denied" in revoked_use.stderr
                     and record_id.encode() not in revoked_list.stdout,
                     "revocation immediately removes use and list authority")

        stop_daemon(process)
        process = None
        damaged_header = b"KSV-DAMAGED-SYNTHETIC"
        journal_before_damage_restore = (active_dir / "journal.ksj").read_bytes()
        (active_dir / "vault.ksv").write_bytes(damaged_header)
        process = start_daemon(daemon, socket_path, data_dir)
        damaged_doctor = run_cli(
            cli, socket_path, "kilix-secrets.test", ["doctor"])
        checks.check(damaged_doctor.returncode == 0
                     and b"initialized=no" in damaged_doctor.stdout
                     and b"storage=damaged" in damaged_doctor.stdout,
                     "daemon exposes damaged storage while remaining available for restore")
        damaged_restore = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["import", "--input", str(backup_path)], bytes(backup_passphrase),
        )
        unknown_retained = list(data_dir.glob(".vault-previous-unknown.*"))
        checks.check(damaged_restore.returncode == 0
                     and len(unknown_retained) == 1
                     and (unknown_retained[0] / "vault.ksv").read_bytes()
                         == damaged_header
                     and (unknown_retained[0] / "journal.ksj").read_bytes()
                         == journal_before_damage_restore,
                     "damaged restore retains exactly 1/1 displaced byte-exact directory")
        damaged_restore_unlock = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"], bytes(passphrase))
        damaged_restored_record = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["run", record_id, "value", "--", sys.executable, str(consumer),
             expected_hash],
        )
        checks.check(damaged_restore_unlock.returncode == 0
                     and damaged_restored_record.returncode == 0
                     and damaged_restored_record.stdout == b"consumer-ok\n",
                     "damaged-state restore recovers the authenticated 1/1 record")

        active_before_reset = (
            (active_dir / "vault.ksv").read_bytes(),
            (active_dir / "journal.ksj").read_bytes(),
        )
        reset_without_confirmation = run_cli(
            cli, socket_path, "kilix-secrets.test", ["reset"],
            secrets.token_bytes(32),
        )
        reset_with_wrong_confirmation = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["reset", "--confirm", "RESET-VAULT-WITHOUT-IDENTITY-LOSS"],
            secrets.token_bytes(32),
        )
        before_reset_list = run_cli(
            cli, socket_path, "kilix-secrets.test", ["list"])
        checks.check(reset_without_confirmation.returncode != 0
                     and reset_with_wrong_confirmation.returncode != 0
                     and record_id.encode() in before_reset_list.stdout
                     and active_before_reset == (
                         (active_dir / "vault.ksv").read_bytes(),
                         (active_dir / "journal.ksj").read_bytes(),
                     ), "vault reset refuses 2/2 absent or mismatched confirmations")
        pre_reset_passphrase.extend(passphrase)
        new_vault_passphrase = secrets.token_bytes(32)
        reset_result, rendered_reset_recovery = run_reset(
            cli, socket_path, "kilix-secrets.test",
            "RESET-VAULT-AND-LOSE-IDENTITY", new_vault_passphrase,
        )
        reset_recovery.extend(rendered_reset_recovery)
        reset_retained = list(data_dir.glob(".vault-reset-retained-*"))
        reset_header = (active_dir / "vault.ksv").read_bytes()
        reset_journal = (active_dir / "journal.ksj").read_bytes()
        checks.check(reset_result.returncode == 0
                     and len(reset_recovery) == 64
                     and b"All peers require revocation or re-pairing"
                         in reset_result.stderr,
                     "confirmed destructive reset returns one new 64-byte recovery secret")
        checks.check(len(reset_retained) == 1
                     and (reset_retained[0] / "vault.ksv").read_bytes()
                         == active_before_reset[0]
                     and (reset_retained[0] / "journal.ksj").read_bytes()
                         == active_before_reset[1],
                     "reset retains exactly 1/1 displaced encrypted generation byte-for-byte")
        checks.check(reset_header[14:30] != active_before_reset[0][14:30]
                     and reset_journal == b"",
                     "reset creates a distinct vault UUID and an empty 0-record generation")
        reset_locked = run_cli(
            cli, socket_path, "kilix-secrets.test", ["list"])
        reset_doctor = run_cli(
            cli, socket_path, "kilix-secrets.test", ["doctor"])
        checks.check(reset_locked.returncode != 0
                     and b"vault locked" in reset_locked.stderr
                     and b"recovery=confirmation-required"
                         in reset_doctor.stdout,
                     "reset globally locks custody pending recovery proof")
        reset_confirmed = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock", "--recovery"],
            bytes(reset_recovery),
        )
        reset_empty = run_cli(
            cli, socket_path, "kilix-secrets.test", ["list"])
        checks.check(reset_confirmed.returncode == 0
                     and reset_empty.returncode == 0
                     and record_id.encode() not in reset_empty.stdout,
                     "recovery proof activates the new empty identity with 0/1 old records")
        reset_lock = run_cli(
            cli, socket_path, "kilix-secrets.test", ["lock"])
        old_identity_unlock = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"],
            bytes(pre_reset_passphrase),
        )
        checks.check(reset_lock.returncode == 0
                     and old_identity_unlock.returncode != 0
                     and b"authentication failure" in old_identity_unlock.stderr,
                     "pre-reset passphrase cannot unwrap the new identity")
        stop_daemon(process)
        process = None
        process = start_daemon(daemon, socket_path, data_dir)
        new_identity_unlock = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"],
            new_vault_passphrase,
        )
        checks.check(new_identity_unlock.returncode == 0,
                     "new passphrase unlocks the reset identity after restart")
        passphrase[:] = new_vault_passphrase

        audit = (data_dir / "audit.log").read_bytes()
        rotated_audit = (data_dir / "audit.log.1").read_bytes()
        vault = (data_dir / "vault-current" / "vault.ksv").read_bytes()
        journal = (data_dir / "vault-current" / "journal.ksj").read_bytes()
        retained_bytes = b"".join(
            (generation / member).read_bytes()
            for generation in list(data_dir.glob(".vault-previous-*"))
                              + list(data_dir.glob(".vault-reset-retained-*"))
            for member in ("vault.ksv", "journal.ksj")
        )
        persistent_bytes = (audit + rotated_audit + vault + journal
                            + retained_bytes + backup_bytes)
        checks.check(bytes(passphrase) not in persistent_bytes,
                     "passphrase is absent from audit and persistent files")
        checks.check(bytes(previous_passphrase)
                     not in persistent_bytes,
                     "retired passphrase is absent from audit and persistent files")
        checks.check(bytes(pre_reset_passphrase) not in persistent_bytes,
                     "pre-reset passphrase is absent from retained encrypted storage")
        checks.check(bytes(recovery) not in persistent_bytes,
                     "recovery secret is absent from audit and persistent files")
        checks.check(bytes(previous_recovery)
                     not in persistent_bytes,
                     "superseded recovery secret is absent from persistent files")
        checks.check(bytes(reset_recovery) not in persistent_bytes,
                     "reset recovery secret is absent from persistent files")
        checks.check(bytes(record_secret) not in persistent_bytes,
                     "record secret is absent from audit and persistent files")
        checks.check(b"Synthetic integration" not in journal,
                     "private record label is encrypted")
        all_audit = audit + rotated_audit
        checks.check(b"event=create" in all_audit and b"event=delete" in all_audit
                     and b"event=recovery" in all_audit
                     and b"event=master-rotation" in all_audit
                     and b"event=export" in all_audit
                     and b"event=import" in all_audit
                     and b"event=grant" in all_audit
                     and b"event=revoke" in all_audit
                     and b"event=vault-reset" in all_audit
                     and b"event=signal-lock" in all_audit,
                     "audit covers record and lifecycle mutations plus the global lock input")
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
        backup_passphrase[:] = b"\x00" * len(backup_passphrase)
        recovery[:] = b"\x00" * len(recovery)
        previous_recovery[:] = b"\x00" * len(previous_recovery)
        reset_recovery[:] = b"\x00" * len(reset_recovery)
        pre_reset_passphrase[:] = b"\x00" * len(pre_reset_passphrase)
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
