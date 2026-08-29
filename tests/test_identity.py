#!/usr/bin/env python3
"""F112/F113 identity custody, anchor, and pollable-lease integration tests."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import select
import shutil
import signal
import subprocess
import tempfile
import time

from test_integration import (
    Checks,
    run_cli,
    run_init,
    run_rotate,
    secret_pipe,
    start_daemon,
    stop_daemon,
)


def wait_line(process: subprocess.Popen[bytes], timeout: float = 10.0) -> bytes:
    if process.stdout is None:
        return b""
    ready, _, _ = select.select([process.stdout], [], [], timeout)
    if not ready:
        return b""
    return process.stdout.readline().strip()


def start_lease(helper: Path, socket_path: Path, record_id: str,
                expected_anchor: str,
                mode: str = "open") -> tuple[subprocess.Popen[bytes], bytes]:
    process = subprocess.Popen(
        [str(helper), mode, str(socket_path), record_id, expected_anchor],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, close_fds=True,
    )
    return process, wait_line(process)


def probe_identity(helper: Path, socket_path: Path, record_id: str,
                   expected_anchor: str = "-") -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(helper), "probe", str(socket_path), record_id, expected_anchor],
        check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=15,
    )


def replace_identity(helper: Path, socket_path: Path, record_id: str,
                     private_key: bytes) -> subprocess.CompletedProcess[bytes]:
    descriptor = secret_pipe(private_key)
    try:
        return subprocess.run(
            [str(helper), "replace", str(socket_path), record_id,
             str(descriptor)],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, pass_fds=(descriptor,), timeout=15,
        )
    finally:
        os.close(descriptor)


def parse_ready(line: bytes) -> tuple[str, str, str, int] | None:
    parts = line.decode("ascii", errors="ignore").split()
    if len(parts) != 5 or parts[0] != "READY":
        return None
    public_key, anchor, vault_uuid, revision_text = parts[1:]
    try:
        revision = int(revision_text, 10)
    except ValueError:
        return None
    if (len(public_key) != 64 or len(anchor) != 64 or len(vault_uuid) != 32
            or revision <= 0
            or any(character not in "0123456789abcdef"
                   for character in public_key + anchor + vault_uuid)):
        return None
    return public_key, anchor, vault_uuid, revision


def parse_info(line: bytes) -> tuple[str, str, str, int] | None:
    if not line.startswith(b"INFO "):
        return None
    return parse_ready(b"READY " + line[5:])


def wait_closed(process: subprocess.Popen[bytes]) -> tuple[bytes, bytes, int]:
    line = wait_line(process, 15.0)
    remaining, error = process.communicate(timeout=15)
    return line + remaining, error, process.returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    options = parser.parse_args()
    build_dir = Path(options.build_dir).resolve()
    daemon = build_dir / "kilix-secretsd"
    cli = build_dir / "kilix-secrets"
    helper = build_dir / "identity-helper"
    scratch = Path(os.environ.get("TMPDIR", ""))
    checks = Checks()
    checks.check(scratch.is_absolute() and scratch.is_dir()
                 and not scratch.is_symlink(),
                 "TMPDIR is an absolute, existing, non-symlink directory")
    root = Path(tempfile.mkdtemp(prefix="ksec-identity.", dir=scratch))
    runtime = root / "runtime"
    socket_path = runtime / "kilix-secrets" / "control.sock"
    data_dir = root / "data"
    runtime.mkdir(mode=0o700)
    process: subprocess.Popen[bytes] | None = None
    waiters: list[subprocess.Popen[bytes]] = []
    passphrase = bytearray(secrets.token_bytes(32))
    changed_passphrase = bytearray(secrets.token_bytes(32))
    recovery = bytearray()
    backup_passphrase = bytearray(secrets.token_bytes(32))
    private_keys = [bytearray(secrets.token_bytes(32)) for _ in range(3)]
    for index, key in enumerate(private_keys):
        key[-1] = 0x41 + index
    backup_path = root / "identity-backup.ksb"
    try:
        process = start_daemon(daemon, socket_path, data_dir)
        initialized, rendered_recovery = run_init(
            cli, socket_path, "kilix-secrets.test", bytes(passphrase))
        recovery.extend(rendered_recovery)
        confirmed = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["unlock", "--recovery"], bytes(recovery))
        checks.check(initialized.returncode == 0 and len(recovery) == 64
                     and confirmed.returncode == 0,
                     "identity fixture initializes and confirms 1/1 recovery slot")

        wrong_owner = run_cli(
            cli, socket_path, "other-app",
            ["add", "--type", "device-identity", "--label", "wrong owner",
             "--field", "private-key"], bytes(private_keys[0]))
        wrong_length = run_cli(
            cli, socket_path, "kilix-pairingd",
            ["add", "--type", "device-identity", "--label", "wrong length",
             "--field", "private-key"], bytes(private_keys[0][:-1]))
        checks.check(wrong_owner.returncode != 0
                     and wrong_length.returncode != 0,
                     "device-identity schema refuses 2/2 wrong-owner or wrong-length records")

        added = run_cli(
            cli, socket_path, "kilix-pairingd",
            ["add", "--type", "device-identity",
             "--label", "F112/F113 local identity",
             "--field", "private-key"], bytes(private_keys[0]))
        record_id = added.stdout.strip().decode("ascii", errors="ignore")
        checks.check(added.returncode == 0 and len(record_id) == 32,
                     "pairing daemon creates one exclusive 32-byte identity record")

        refused_grant = run_cli(
            cli, socket_path, "kilix-pairingd",
            ["grant", record_id, "other-app", "--verbs", "use"])
        refused_generic_get = run_cli(
            cli, socket_path, "kilix-pairingd",
            ["run", record_id, "private-key", "--", "/bin/true"])
        checks.check(refused_grant.returncode != 0
                     and b"denied" in refused_grant.stderr
                     and refused_generic_get.returncode != 0
                     and b"denied" in refused_generic_get.stderr,
                     "identity custody refuses 2/2 grants and generic secret delivery")

        public_info_result = subprocess.run(
            [str(helper), "info", str(socket_path), record_id, "-"],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=15,
        )
        public_info = parse_info(public_info_result.stdout.strip())
        first_probe = probe_identity(helper, socket_path, record_id)
        first_info = parse_ready(first_probe.stdout.strip())
        checks.check(public_info_result.returncode == 0
                     and public_info is not None
                     and first_probe.returncode == 0 and first_info is not None
                     and public_info == first_info
                     and all(bytes(key) not in first_probe.stdout
                             + first_probe.stderr + public_info_result.stdout
                             + public_info_result.stderr
                             for key in private_keys),
                     "public-only and private-open paths agree on 4/4 metadata values and print 0/3 private keys")
        if first_info is None:
            raise RuntimeError("identity probe did not return parseable metadata")
        public_one, anchor_one, uuid_one, revision_one = first_info

        lease_limit = subprocess.run(
            [str(helper), "limit", str(socket_path), record_id, "-"],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=20,
        )
        checks.check(lease_limit.returncode == 0
                     and lease_limit.stdout
                         == b"LIMIT 128/128 RECLAIM 1/1\n",
                     "identity leases fill 128/128 slots, refuse the 129th, and reclaim 1/1 closed reader")
        time.sleep(1.1)

        lock_waiter, ready = start_lease(
            helper, socket_path, record_id, anchor_one)
        waiters.append(lock_waiter)
        doctor_live = run_cli(
            cli, socket_path, "kilix-secrets.test", ["doctor"])
        process.send_signal(signal.SIGUSR1)
        closed, close_error, close_status = wait_closed(lock_waiter)
        waiters.remove(lock_waiter)
        checks.check(parse_ready(ready) is not None
                     and b"identity_leases=1/128" in doctor_live.stdout
                     and closed == b"CLOSED" and close_error == b""
                     and close_status == 0,
                     "vault lock closes the active 1/128 pollable identity lease")
        locked_probe = probe_identity(helper, socket_path, record_id, anchor_one)
        locked_info = subprocess.run(
            [str(helper), "info", str(socket_path), record_id, anchor_one],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=15,
        )
        checks.check(locked_probe.returncode != 0
                     and locked_info.returncode != 0
                     and b"ERROR vault locked" in locked_probe.stdout
                     and b"ERROR vault locked" in locked_info.stdout,
                     "locked vault refuses both 2/2 private and public identity access paths")

        unlocked = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"],
            bytes(passphrase))
        checks.check(unlocked.returncode == 0,
                     "passphrase restores identity custody after global lock")

        expiry_waiter, ready = start_lease(
            helper, socket_path, record_id, anchor_one, mode="expire")
        waiters.append(expiry_waiter)
        closed, close_error, close_status = wait_closed(expiry_waiter)
        waiters.remove(expiry_waiter)
        checks.check(parse_ready(ready) is not None and closed == b"CLOSED"
                     and close_error == b"" and close_status == 0,
                     "capability expiry closes its active 1/1 pollable lease")

        replace_waiter, ready = start_lease(
            helper, socket_path, record_id, anchor_one)
        waiters.append(replace_waiter)
        replaced = replace_identity(
            helper, socket_path, record_id, bytes(private_keys[1]))
        closed, close_error, close_status = wait_closed(replace_waiter)
        waiters.remove(replace_waiter)
        checks.check(parse_ready(ready) is not None
                     and replaced.returncode == 0
                     and replaced.stdout == b"REPLACED\n"
                     and closed == b"CLOSED" and close_error == b""
                     and close_status == 0,
                     "local identity-key rotation closes its 1/1 live lease")
        old_anchor_probe = subprocess.run(
            [str(helper), "info", str(socket_path), record_id, anchor_one],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=15,
        )
        checks.check(old_anchor_probe.returncode != 0
                     and b"ERROR identity generation conflict"
                         in old_anchor_probe.stdout,
                     "stale expected anchor fails closed with 1/1 generation conflict")
        second_probe = probe_identity(helper, socket_path, record_id)
        second_info = parse_ready(second_probe.stdout.strip())
        checks.check(second_probe.returncode == 0 and second_info is not None,
                     "rotated identity opens with a fresh unbound probe")
        if second_info is None:
            raise RuntimeError("rotated identity probe failed")
        public_two, anchor_two, uuid_two, revision_two = second_info
        checks.check(public_two != public_one and anchor_two != anchor_one
                     and uuid_two == uuid_one and revision_two > revision_one,
                     "key rotation changes 2/2 public/anchor values while preserving 1/1 vault UUID")

        rotation_waiter, ready = start_lease(
            helper, socket_path, record_id, anchor_two)
        waiters.append(rotation_waiter)
        changed = run_cli(
            cli, socket_path, "kilix-secrets.test", ["passwd"],
            bytes(changed_passphrase))
        no_early_close = True
        if rotation_waiter.stdout is not None:
            readable, _, _ = select.select([rotation_waiter.stdout], [], [], 0.5)
            no_early_close = not readable and rotation_waiter.poll() is None
        checks.check(changed.returncode == 0 and no_early_close,
                     "passphrase-slot rewrap preserves the active 1/1 identity lease")
        rotated = run_rotate(
            cli, socket_path, "kilix-secrets.test",
            bytes(changed_passphrase), bytes(recovery))
        closed, close_error, close_status = wait_closed(rotation_waiter)
        waiters.remove(rotation_waiter)
        checks.check(parse_ready(ready) is not None and rotated.returncode == 0
                     and closed == b"CLOSED" and close_error == b""
                     and close_status == 0,
                     "master-key rotation re-encrypts custody and closes 1/1 live lease")
        stable_after_master = probe_identity(
            helper, socket_path, record_id, anchor_two)
        stable_info = parse_ready(stable_after_master.stdout.strip())
        checks.check(stable_after_master.returncode == 0
                     and stable_info is not None
                     and stable_info[0] == public_two
                     and stable_info[1] == anchor_two
                     and stable_info[2] == uuid_two
                     and stable_info[3] == revision_two,
                     "master rotation preserves all 4/4 identity anchor components")

        exported = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["export", "--output", str(backup_path)],
            bytes(backup_passphrase))
        checks.check(exported.returncode == 0 and backup_path.is_file(),
                     "encrypted backup captures the anchored identity generation")
        replaced_again = replace_identity(
            helper, socket_path, record_id, bytes(private_keys[2]))
        third_probe = probe_identity(helper, socket_path, record_id)
        third_info = parse_ready(third_probe.stdout.strip())
        checks.check(replaced_again.returncode == 0 and third_info is not None
                     and third_info[1] != anchor_two,
                     "second explicit key rotation creates a distinct anchor")
        if third_info is None:
            raise RuntimeError("second rotated identity probe failed")
        anchor_three = third_info[1]

        restore_waiter, ready = start_lease(
            helper, socket_path, record_id, anchor_three)
        waiters.append(restore_waiter)
        restored = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["import", "--input", str(backup_path)],
            bytes(backup_passphrase))
        closed, close_error, close_status = wait_closed(restore_waiter)
        waiters.remove(restore_waiter)
        checks.check(parse_ready(ready) is not None and restored.returncode == 0
                     and closed == b"CLOSED" and close_error == b""
                     and close_status == 0,
                     "backup restore globally closes the active 1/1 identity lease")
        restored_unlock = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"],
            bytes(changed_passphrase))
        restored_expected = probe_identity(
            helper, socket_path, record_id, anchor_two)
        restored_conflict = probe_identity(
            helper, socket_path, record_id, anchor_three)
        restored_info = parse_ready(restored_expected.stdout.strip())
        checks.check(restored_unlock.returncode == 0
                     and restored_expected.returncode == 0
                     and restored_info is not None
                     and restored_info[0] == public_two
                     and restored_info[1] == anchor_two
                     and restored_conflict.returncode != 0
                     and b"generation conflict" in restored_conflict.stdout,
                     "restore accepts 2/2 backed-up public/anchor values and rejects 1/1 displaced anchor")

        stop_waiter, ready = start_lease(
            helper, socket_path, record_id, anchor_two)
        waiters.append(stop_waiter)
        stop_daemon(process)
        process = None
        closed, close_error, close_status = wait_closed(stop_waiter)
        waiters.remove(stop_waiter)
        checks.check(parse_ready(ready) is not None and closed == b"CLOSED"
                     and close_error == b"" and close_status == 0,
                     "daemon stop closes the active 1/1 pollable identity lease")
        process = start_daemon(daemon, socket_path, data_dir)
        restart_unlock = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"],
            bytes(changed_passphrase))
        checks.check(restart_unlock.returncode == 0,
                     "daemon restart restores custody only after fresh authorization and unlock")

        delete_waiter, ready = start_lease(
            helper, socket_path, record_id, anchor_two)
        waiters.append(delete_waiter)
        deleted = run_cli(
            cli, socket_path, "kilix-pairingd",
            ["delete", record_id, "--confirm", record_id])
        closed, close_error, close_status = wait_closed(delete_waiter)
        waiters.remove(delete_waiter)
        checks.check(parse_ready(ready) is not None and deleted.returncode == 0
                     and closed == b"CLOSED" and close_error == b""
                     and close_status == 0,
                     "confirmed local-key deletion closes the active 1/1 lease")
        missing_probe = probe_identity(helper, socket_path, record_id, anchor_two)
        doctor_empty = run_cli(
            cli, socket_path, "kilix-secrets.test", ["doctor"])
        checks.check(missing_probe.returncode != 0
                     and b"ERROR not found" in missing_probe.stdout
                     and b"identity_leases=0/128" in doctor_empty.stdout,
                     "deleted identity returns not-found and leaves 0/128 leases")

        persistent = b"".join(
            path.read_bytes() for path in data_dir.rglob("*") if path.is_file()
        ) + backup_path.read_bytes()
        checks.check(all(bytes(key) not in persistent for key in private_keys),
                     "persistent vault, audit, retained generations, and backup expose 0/3 raw private keys")
        audit = b"".join(
            path.read_bytes() for path in data_dir.glob("audit.log*")
            if path.is_file()
        )
        checks.check(b"event=identity-open" in audit
                     and b"event=replace" in audit
                     and b"event=delete" in audit,
                     "audit covers all 3/3 identity open/rotate/delete classes")
    finally:
        for waiter in waiters:
            if waiter.poll() is None:
                waiter.send_signal(signal.SIGTERM)
                try:
                    waiter.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    waiter.kill()
                    waiter.wait(timeout=5)
            if waiter.stdout is not None:
                waiter.stdout.close()
            if waiter.stderr is not None:
                waiter.stderr.close()
        if process is not None:
            stop_daemon(process)
        passphrase[:] = b"\x00" * len(passphrase)
        changed_passphrase[:] = b"\x00" * len(changed_passphrase)
        recovery[:] = b"\x00" * len(recovery)
        backup_passphrase[:] = b"\x00" * len(backup_passphrase)
        for key in private_keys:
            key[:] = b"\x00" * len(key)
        resolved = root.resolve()
        required_parent = scratch.resolve()
        if (resolved.parent == required_parent
                and resolved.name.startswith("ksec-identity.")):
            shutil.rmtree(resolved)
        else:
            checks.check(False, "refused unsafe identity-test cleanup path")
    print(f"identity checks: {checks.total - checks.failed}/{checks.total} passed")
    return 0 if checks.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
