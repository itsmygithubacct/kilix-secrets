#!/usr/bin/env python3
"""STATUS and WATCH integration tests."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from test_integration import (
    Checks,
    run_cli,
    run_init,
    run_reset,
    run_rotate,
    stop_daemon,
    wait_for_socket,
)


def wait_line(process: subprocess.Popen[bytes], timeout: float) -> bytes:
    if process.stdout is None:
        return b""
    ready, _, _ = select.select([process.stdout], [], [], timeout)
    if not ready:
        return b""
    return process.stdout.readline().strip()


def start_daemon_idle(daemon: Path, socket_path: Path, data_dir: Path,
                      idle_seconds: str) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [str(daemon), "--socket", str(socket_path), "--data-dir", str(data_dir),
         "--development-kdf-ops", "3", "--development-kdf-mem-mib", "256",
         "--idle-seconds", idle_seconds],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, close_fds=True,
    )
    if not wait_for_socket(socket_path, process):
        process.kill()
        process.wait(timeout=5)
        error = process.stderr.read() if process.stderr is not None else b""
        raise RuntimeError(
            f"daemon did not create socket (stderr bytes={len(error)})")
    return process


def daemon_fd_count(pid: int) -> int | None:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except PermissionError:
        return None


def daemon_fd_size(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
        if line.startswith("FDSize:"):
            return int(line.split()[1])
    raise RuntimeError("daemon status has no FDSize")


def start_helper(helper: Path, args: list[str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [str(helper), *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
    )


def finish_helper(process: subprocess.Popen[bytes]) -> bytes:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    error = b""
    if process.stderr is not None:
        error = process.stderr.read()
        process.stderr.close()
    if process.stdout is not None:
        rest = process.stdout.read()
        if rest:
            error += rest
        process.stdout.close()
    return error


def run_helper(helper: Path, args: list[str],
               timeout: float) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(helper), *args], check=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
    )


def status_result(helper: Path, socket_path: Path, verb: str,
                  scoped: bool = False) -> subprocess.CompletedProcess[bytes]:
    args = ["status", str(socket_path), verb]
    if scoped:
        args.append("scoped")
    return run_helper(helper, args, 15)


def open_watch(helper: Path, socket_path: Path, timeout_ms: int,
               lifetime: int | None = None) -> tuple[subprocess.Popen[bytes], bytes]:
    args = ["watch", str(socket_path), str(timeout_ms)]
    if lifetime is not None:
        args.append(str(lifetime))
    process = start_helper(helper, args)
    return process, wait_line(process, 10.0)


def watch_hangup(helper: Path, socket_path: Path, helpers: list[subprocess.Popen[bytes]],
                 action) -> tuple[bytes, float, bytes]:
    process, ready = open_watch(helper, socket_path, 30000)
    helpers.append(process)
    if ready != b"READY":
        error = finish_helper(process)
        helpers.remove(process)
        return ready, 0.0, error
    action()
    started = time.monotonic()
    line = wait_line(process, 2.0)
    elapsed = time.monotonic() - started
    error = finish_helper(process)
    helpers.remove(process)
    return line, elapsed, error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    options = parser.parse_args()
    build_dir = Path(options.build_dir).resolve()
    daemon = build_dir / "kilix-secretsd"
    cli = build_dir / "kilix-secrets"
    helper = build_dir / "status-helper"
    scratch = Path(os.environ.get("TMPDIR", ""))
    checks = Checks()
    checks.check(scratch.is_absolute() and scratch.is_dir()
                 and not scratch.is_symlink(),
                 "TMPDIR is an absolute, existing, non-symlink directory")
    root = Path(tempfile.mkdtemp(prefix="ksec-status.", dir=scratch))
    runtime = root / "runtime"
    socket_path = runtime / "kilix-secrets" / "control.sock"
    data_dir = root / "data"
    runtime.mkdir(mode=0o700)
    checks.check(len(str(socket_path)) < 108,
                 "private socket path fits the 108-byte AF_UNIX limit")
    process: subprocess.Popen[bytes] | None = None
    helpers: list[subprocess.Popen[bytes]] = []
    passphrase = bytearray(secrets.token_bytes(32))
    recovery = bytearray()
    backup_passphrase = bytearray(secrets.token_bytes(32))
    reset_recovery = bytearray()
    try:
        process = start_daemon_idle(daemon, socket_path, data_dir, "60")
        no_vault_doctor = status_result(helper, socket_path, "doctor")
        no_vault_create = status_result(helper, socket_path, "create")
        no_vault_scoped = status_result(helper, socket_path, "doctor", scoped=True)
        checks.check(no_vault_doctor.returncode == 0
                     and no_vault_doctor.stdout == b"FLAGS 0\n"
                     and no_vault_doctor.stderr == b""
                     and no_vault_create.returncode == 0
                     and no_vault_create.stdout == b"FLAGS 0\n"
                     and no_vault_scoped.returncode == 0
                     and no_vault_scoped.stdout == b"FLAGS 0\n",
                     "STATUS with doctor, create, and record-scoped caps is 0 before a vault exists")
        expired = run_helper(helper, ["status-expire", str(socket_path)], 15)
        checks.check(expired.returncode == 0
                     and expired.stdout == b"FLAGS 0\nERROR denied\n"
                     and expired.stderr == b"",
                     "expired capability fails STATUS with denied (KSEC_ERR_DENIED)")
        locked_watch = run_helper(helper, ["watch", str(socket_path), "2000"], 15)
        checks.check(locked_watch.returncode == 3
                     and locked_watch.stdout == b"ERROR vault locked\n"
                     and locked_watch.stderr == b"",
                     "WATCH before a vault exists is vault locked")

        initialized, rendered = run_init(
            cli, socket_path, "kilix-secrets.test", bytes(passphrase))
        recovery.extend(rendered)
        unconfirmed = status_result(helper, socket_path, "doctor")
        unconfirmed_watch = run_helper(
            helper, ["watch", str(socket_path), "2000"], 15)
        checks.check(initialized.returncode == 0 and len(recovery) == 64
                     and unconfirmed.returncode == 0
                     and unconfirmed.stdout == b"FLAGS 1\n"
                     and unconfirmed_watch.returncode == 3
                     and unconfirmed_watch.stdout == b"ERROR vault locked\n",
                     "initialized unconfirmed vault reports flags 1 and WATCH is vault locked")

        confirmed = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["unlock", "--recovery"], bytes(recovery))
        unlocked_doctor = status_result(helper, socket_path, "doctor")
        unlocked_create = status_result(helper, socket_path, "create")
        checks.check(confirmed.returncode == 0
                     and unlocked_doctor.returncode == 0
                     and unlocked_doctor.stdout == b"FLAGS 7\n"
                     and unlocked_create.returncode == 0
                     and unlocked_create.stdout == b"FLAGS 7\n",
                     "confirmed unlocked vault reports flags 7 for doctor and create caps")

        def lock_vault() -> None:
            completed = run_cli(cli, socket_path, "kilix-secrets.test", ["lock"])
            checks.check(completed.returncode == 0, "explicit LOCK succeeds")

        line, elapsed, error = watch_hangup(
            helper, socket_path, helpers, lock_vault)
        checks.check(line == b"CLOSED" and elapsed <= 2.0 and error == b"",
                     "LOCK closes the watch with no readable bytes "
                     f"(line={line!r} elapsed={elapsed:.3f}s)")
        locked_doctor = status_result(helper, socket_path, "doctor")
        locked_create = status_result(helper, socket_path, "create")
        locked_again = run_helper(helper, ["watch", str(socket_path), "2000"], 15)
        checks.check(locked_doctor.stdout == b"FLAGS 3\n"
                     and locked_create.stdout == b"FLAGS 3\n"
                     and locked_again.stdout == b"ERROR vault locked\n",
                     "STATUS while locked is flags 3 and WATCH is vault locked")

        relocked = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"], bytes(passphrase))
        checks.check(relocked.returncode == 0, "passphrase unlocks after LOCK")

        def signal_lock() -> None:
            if process is not None:
                process.send_signal(signal.SIGUSR1)

        line, elapsed, error = watch_hangup(
            helper, socket_path, helpers, signal_lock)
        checks.check(line == b"CLOSED" and elapsed <= 2.0 and error == b"",
                     "SIGUSR1 closes the watch with no readable bytes "
                     f"(line={line!r} elapsed={elapsed:.3f}s)")
        after_signal = status_result(helper, socket_path, "read")
        checks.check(after_signal.stdout == b"FLAGS 3\n",
                     "STATUS after SIGUSR1 is flags 3 on a fresh capability")

        resigned = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"], bytes(passphrase))
        checks.check(resigned.returncode == 0, "passphrase unlocks after SIGUSR1")

        def rotate() -> None:
            completed = run_rotate(
                cli, socket_path, "kilix-secrets.test",
                bytes(passphrase), bytes(recovery))
            checks.check(completed.returncode == 0, "master rotation succeeds")

        line, elapsed, error = watch_hangup(helper, socket_path, helpers, rotate)
        checks.check(line == b"CLOSED" and elapsed <= 2.0 and error == b"",
                     "master rotation closes the watch with no readable bytes "
                     f"(line={line!r} elapsed={elapsed:.3f}s)")
        after_rotate = status_result(helper, socket_path, "doctor")
        checks.check(after_rotate.stdout == b"FLAGS 7\n",
                     "STATUS after master rotation is flags 7 without another unlock")

        backup_path = root / "status-backup.ksb"
        exported = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["export", "--output", str(backup_path)], bytes(backup_passphrase))
        checks.check(exported.returncode == 0 and backup_path.is_file(),
                     "encrypted backup is available for the import hangup")

        def import_backup() -> None:
            completed = run_cli(
                cli, socket_path, "kilix-secrets.test",
                ["import", "--input", str(backup_path)], bytes(backup_passphrase))
            checks.check(completed.returncode == 0, "backup import succeeds")

        line, elapsed, error = watch_hangup(
            helper, socket_path, helpers, import_backup)
        checks.check(line == b"CLOSED" and elapsed <= 2.0 and error == b"",
                     "backup import closes the watch with no readable bytes "
                     f"(line={line!r} elapsed={elapsed:.3f}s)")
        after_import = status_result(helper, socket_path, "doctor")
        checks.check(after_import.stdout == b"FLAGS 3\n",
                     "STATUS after import is flags 3")

        restored = run_cli(
            cli, socket_path, "kilix-secrets.test", ["unlock"], bytes(passphrase))
        checks.check(restored.returncode == 0, "passphrase unlocks the imported vault")

        def reset_vault() -> None:
            completed, rendered_reset = run_reset(
                cli, socket_path, "kilix-secrets.test",
                "RESET-VAULT-AND-LOSE-IDENTITY", bytes(passphrase))
            reset_recovery.extend(rendered_reset)
            checks.check(completed.returncode == 0 and len(reset_recovery) == 64,
                         "destructive reset succeeds")

        line, elapsed, error = watch_hangup(
            helper, socket_path, helpers, reset_vault)
        checks.check(line == b"CLOSED" and elapsed <= 2.0 and error == b"",
                     "destructive reset closes the watch with no readable bytes "
                     f"(line={line!r} elapsed={elapsed:.3f}s)")
        after_reset = status_result(helper, socket_path, "doctor")
        checks.check(after_reset.stdout == b"FLAGS 1\n",
                     "STATUS after reset is flags 1")

        reconfirmed = run_cli(
            cli, socket_path, "kilix-secrets.test",
            ["unlock", "--recovery"], bytes(reset_recovery))
        checks.check(reconfirmed.returncode == 0,
                     "recovery unlock confirms the reset vault")

        expiry_watch, ready = open_watch(helper, socket_path, 8000, lifetime=2)
        helpers.append(expiry_watch)
        started = time.monotonic()
        expiry_line = wait_line(expiry_watch, 8.0)
        expiry_elapsed = time.monotonic() - started
        expiry_error = finish_helper(expiry_watch)
        helpers.remove(expiry_watch)
        checks.check(ready == b"READY" and expiry_line == b"CLOSED"
                     and expiry_error == b""
                     and 1.0 <= expiry_elapsed <= 6.5,
                     "2-second capability expiry closes the watch with no readable bytes "
                     f"(ready={ready!r} line={expiry_line!r} elapsed={expiry_elapsed:.3f}s)")

        passed = run_helper(helper, ["watch-pass", str(socket_path)], 15)
        checks.check(passed.returncode == 0 and passed.stdout == b"CLOSED\n"
                     and passed.stderr == b"",
                     "disconnect of the requesting connection closes a watch held elsewhere")

        fd_before = daemon_fd_size(process.pid)
        listed_before = daemon_fd_count(process.pid)
        limit = run_helper(helper, ["watch-limit", str(socket_path)], 20)
        checks.check(limit.returncode == 0
                     and limit.stdout == b"LIMIT 128/128 QUIET 128/128\nDROPPED\n"
                     and limit.stderr == b"",
                     "128 watches are quiet and the 129th is limit exceeded")
        # Eight waves of 128 is 1024 daemon-held ends. PR_SET_DUMPABLE makes
        # /proc/PID/fd root-only, so closure is observed through FDSize, which
        # stays at one wave's table when each wave's ends are closed and grows
        # past 1024 when they are retained. A listable fd directory, when the
        # kernel allows it, is compared directly.
        pressure = run_helper(
            helper, ["watch-pressure", str(socket_path), "8"], 60)
        fd_after = daemon_fd_size(process.pid)
        listed_after = daemon_fd_count(process.pid)
        listed_ok = True
        if listed_before is not None and listed_after is not None:
            deadline = time.monotonic() + 4.0
            while time.monotonic() < deadline and listed_after != listed_before:
                time.sleep(0.1)
                listed_after = daemon_fd_count(process.pid)
            listed_ok = listed_after == listed_before
        checks.check(pressure.returncode == 0
                     and pressure.stdout == b"PRESSURE 8/8\n"
                     and pressure.stderr == b""
                     and fd_before <= fd_after < 1024
                     and listed_ok,
                     "eight full watch waves close the daemon ends "
                     f"(FDSize {fd_before} -> {fd_after}, "
                     f"listed {listed_before} -> {listed_after}, "
                     f"stdout={pressure.stdout!r})")

        audit = b"".join(
            path.read_bytes() for path in data_dir.glob("audit.log*")
            if path.is_file()
        )
        checks.check(b"event=status" not in audit and b"event=watch" not in audit,
                     "STATUS and WATCH write no audit events")

        stop_watch, ready = open_watch(helper, socket_path, 15000)
        helpers.append(stop_watch)
        checks.check(ready == b"READY", "watch is open before daemon SIGTERM")
        process.send_signal(signal.SIGTERM)
        started = time.monotonic()
        stop_line = wait_line(stop_watch, 2.0)
        stop_elapsed = time.monotonic() - started
        process.wait(timeout=5)
        stop_error = finish_helper(stop_watch)
        helpers.remove(stop_watch)
        checks.check(stop_line == b"CLOSED" and stop_elapsed <= 2.0
                     and stop_error == b"" and process.returncode is not None,
                     "daemon SIGTERM closes the watch with no readable bytes "
                     f"(line={stop_line!r} elapsed={stop_elapsed:.3f}s)")
        stop_daemon(process)
        process = None

        idle_root = root / "idle"
        idle_runtime = idle_root / "runtime"
        idle_socket = idle_runtime / "kilix-secrets" / "control.sock"
        idle_data = idle_root / "data"
        idle_runtime.mkdir(parents=True, mode=0o700)
        idle = start_daemon_idle(daemon, idle_socket, idle_data, "8")
        process = idle
        idle_init, idle_rendered = run_init(
            cli, idle_socket, "kilix-secrets.test", bytes(passphrase))
        idle_recovery = bytearray(idle_rendered)
        idle_unlock = run_cli(
            cli, idle_socket, "kilix-secrets.test",
            ["unlock", "--recovery"], bytes(idle_recovery))
        idle_watch, idle_ready = open_watch(helper, idle_socket, 20000)
        helpers.append(idle_watch)
        observed = None
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            current = status_result(helper, idle_socket, "doctor")
            if current.stdout == b"FLAGS 3\n":
                observed = time.monotonic()
                break
            time.sleep(0.2)
        idle_line = wait_line(idle_watch, 2.0) if observed is not None else b""
        idle_elapsed = 0.0 if observed is None else time.monotonic() - observed
        idle_error = finish_helper(idle_watch)
        helpers.remove(idle_watch)
        checks.check(idle_init.returncode == 0 and idle_unlock.returncode == 0
                     and idle_ready == b"READY" and observed is not None
                     and idle_line == b"CLOSED" and idle_elapsed <= 2.0
                     and idle_error == b"",
                     "idle-seconds 8 closes the watch within 2s of STATUS flags 3 "
                     f"(ready={idle_ready!r} line={idle_line!r} elapsed={idle_elapsed:.3f}s)")
        idle_recovery[:] = b"\x00" * len(idle_recovery)
        stop_daemon(process)
        process = None
    finally:
        for waiter in list(helpers):
            finish_helper(waiter)
        helpers.clear()
        if process is not None:
            stop_daemon(process)
        passphrase[:] = b"\x00" * len(passphrase)
        recovery[:] = b"\x00" * len(recovery)
        backup_passphrase[:] = b"\x00" * len(backup_passphrase)
        reset_recovery[:] = b"\x00" * len(reset_recovery)
        resolved = root.resolve()
        required_parent = scratch.resolve()
        if (resolved.parent == required_parent
                and resolved.name.startswith("ksec-status.")):
            shutil.rmtree(resolved)
        else:
            checks.check(False, "refused unsafe status-watch cleanup path")
    print(f"status-watch checks: {checks.total - checks.failed}/{checks.total} passed")
    return 0 if checks.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
