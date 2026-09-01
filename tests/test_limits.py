#!/usr/bin/env python3
"""Bounded connection, request-queue, worker, and RSS load checks."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time


MAX_CONNECTIONS = 64
REQUEST_ROUNDS = 64
OVERFLOW_CONNECTIONS = 16
RSS_DELTA_LIMIT_KIB = 8192
PROTOCOL_MAGIC = 0x4B534543
PROTOCOL_VERSION = 1
OP_INIT = 3
RESULT_DENIED = 2


class Checks:
    def __init__(self) -> None:
        self.total = 0
        self.failed = 0

    def check(self, condition: bool, message: str) -> None:
        self.total += 1
        if not condition:
            self.failed += 1
            print(f"FAIL limits: {message}", file=sys.stderr)


def wait_for_socket(socket_path: Path,
                    process: subprocess.Popen[bytes]) -> bool:
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
        raise RuntimeError(
            f"daemon did not create socket (stderr bytes={len(error)})")
    return process


def stop_daemon(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=10)
    if process.stderr is not None:
        process.stderr.close()


def process_status(pid: int) -> tuple[int, int]:
    values: dict[str, int] = {}
    status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    for line in status.splitlines():
        if line.startswith("VmRSS:") or line.startswith("Threads:"):
            fields = line.split()
            values[fields[0][:-1]] = int(fields[1])
    return values.get("VmRSS", -1), values.get("Threads", -1)


def request_packet(request_id: int) -> bytes:
    return struct.pack(">IHHIQI", PROTOCOL_MAGIC, PROTOCOL_VERSION,
                       OP_INIT, 0, request_id, 0)


def denied_reply(packet: bytes, request_id: int) -> bool:
    if len(packet) != 28:
        return False
    magic, version, operation, flags, observed_id, payload_len = \
        struct.unpack(">IHHIQI", packet[:24])
    result, = struct.unpack(">I", packet[24:])
    return (magic == PROTOCOL_MAGIC and version == PROTOCOL_VERSION
            and operation == OP_INIT and flags == 0
            and observed_id == request_id and payload_len == 4
            and result == RESULT_DENIED)


def overflow_is_closed(socket_path: Path) -> bool:
    descriptor = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    descriptor.settimeout(5.0)
    try:
        descriptor.connect(str(socket_path))
        try:
            return descriptor.recv(1) == b""
        except (ConnectionResetError, BrokenPipeError):
            return True
        except socket.timeout:
            return False
    finally:
        descriptor.close()



def check_over_long_socket_path_is_diagnosed(checks: "Checks", daemon: Path,
                                            root: Path) -> None:
    """SEC-02: past sun_path's limit the daemon must say why, not just exit."""
    deep = root / ("d" * 60) / ("e" * 60) / ("f" * 60)
    deep.mkdir(parents=True, exist_ok=True)
    socket_path = deep / "control.sock"
    data_dir = root / "sec02-data"
    data_dir.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [str(daemon), "--socket", str(socket_path), "--data-dir", str(data_dir)],
        capture_output=True, text=True, timeout=30)
    checks.check(len(str(socket_path)) > 107,
                 "the probe path exceeds the AF_UNIX sun_path limit")
    checks.check(completed.returncode != 0,
                 "an over-long socket path fails closed")
    checks.check("socket path is" in completed.stderr
                 and "maximum is 107" in completed.stderr,
                 "an over-long socket path is diagnosed, not silent")
    checks.check(not socket_path.exists(), "no socket is left behind")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    options = parser.parse_args()
    daemon = Path(options.build_dir).resolve() / "kilix-secretsd"
    scratch = Path(os.environ.get("TMPDIR", ""))
    checks = Checks()
    checks.check(scratch.is_absolute() and scratch.is_dir()
                 and not scratch.is_symlink(),
                 "TMPDIR is an absolute existing non-symlink directory")
    root = Path(tempfile.mkdtemp(prefix="ksec-limits.", dir=scratch))
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    check_over_long_socket_path_is_diagnosed(checks, daemon, root)
    socket_path = runtime / "kilix-secrets" / "control.sock"
    data_dir = root / "data"
    process: subprocess.Popen[bytes] | None = None
    connections: list[socket.socket] = []
    processed = 0
    overflow_closed = 0
    max_rss_kib = -1
    baseline_rss_kib = -1
    try:
        process = start_daemon(daemon, socket_path, data_dir)
        time.sleep(0.1)
        baseline_rss_kib, baseline_threads = process_status(process.pid)
        checks.check(process.poll() is None and baseline_rss_kib > 0,
                     "daemon establishes one measurable bounded baseline")
        checks.check(baseline_threads == 1,
                     "daemon begins with exactly 1/1 worker thread")

        for _ in range(MAX_CONNECTIONS):
            descriptor = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            descriptor.settimeout(10.0)
            descriptor.connect(str(socket_path))
            connections.append(descriptor)
        accepted = 0
        for index, descriptor in enumerate(connections):
            descriptor.sendall(request_packet(100000 + index))
        for index, descriptor in enumerate(connections):
            if denied_reply(descriptor.recv(128), 100000 + index):
                accepted += 1
        checks.check(accepted == MAX_CONNECTIONS,
                     "daemon services exactly 64/64 bounded connection slots")

        for round_index in range(REQUEST_ROUNDS):
            for connection_index, descriptor in enumerate(connections):
                request_id = (round_index * MAX_CONNECTIONS
                              + connection_index + 1)
                descriptor.sendall(request_packet(request_id))
        queued_rss_kib, _ = process_status(process.pid)
        max_rss_kib = max(baseline_rss_kib, queued_rss_kib)
        for round_index in range(REQUEST_ROUNDS):
            for connection_index, descriptor in enumerate(connections):
                request_id = (round_index * MAX_CONNECTIONS
                              + connection_index + 1)
                packet = descriptor.recv(128)
                if denied_reply(packet, request_id):
                    processed += 1
            observed_rss_kib, _ = process_status(process.pid)
            max_rss_kib = max(max_rss_kib, observed_rss_kib)
        expected_requests = MAX_CONNECTIONS * REQUEST_ROUNDS
        checks.check(processed == expected_requests,
                     "daemon processes 4,096/4,096 queued framed requests")

        for _ in range(OVERFLOW_CONNECTIONS):
            if overflow_is_closed(socket_path):
                overflow_closed += 1
        checks.check(overflow_closed == OVERFLOW_CONNECTIONS,
                     "full daemon closes 16/16 overflow connections")

        final_rss_kib, final_threads = process_status(process.pid)
        max_rss_kib = max(max_rss_kib, final_rss_kib)
        rss_delta_kib = max_rss_kib - baseline_rss_kib
        checks.check(final_threads == 1,
                     "daemon remains at exactly 1/1 worker thread under load")
        checks.check(0 <= rss_delta_kib <= RSS_DELTA_LIMIT_KIB,
                     "daemon RSS delta stays within 8,192/8,192 KiB")

        for descriptor in connections:
            descriptor.close()
        connections.clear()
        time.sleep(0.1)
        reclaimed = 0
        for index in range(MAX_CONNECTIONS):
            descriptor = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            descriptor.settimeout(10.0)
            descriptor.connect(str(socket_path))
            connections.append(descriptor)
            descriptor.sendall(request_packet(200000 + index))
        for index, descriptor in enumerate(connections):
            if denied_reply(descriptor.recv(128), 200000 + index):
                reclaimed += 1
        checks.check(reclaimed == MAX_CONNECTIONS and process.poll() is None,
                     "closing 64/64 clients reclaims all 64/64 slots")
    finally:
        for descriptor in connections:
            descriptor.close()
        if process is not None:
            stop_daemon(process)
        resolved = root.resolve()
        required_parent = scratch.resolve()
        if (resolved.parent == required_parent
                and resolved.name.startswith("ksec-limits.")):
            shutil.rmtree(resolved)
        else:
            checks.check(False, "refused unsafe limits-test cleanup path")
    rss_delta_kib = (max_rss_kib - baseline_rss_kib
                     if max_rss_kib >= 0 and baseline_rss_kib >= 0 else -1)
    print(f"limit checks: {checks.total - checks.failed}/{checks.total} passed")
    print(f"load requests: {processed}/{MAX_CONNECTIONS * REQUEST_ROUNDS}; "
          f"connection slots: {MAX_CONNECTIONS}/{MAX_CONNECTIONS}; "
          f"overflow closed: {overflow_closed}/{OVERFLOW_CONNECTIONS}; "
          f"RSS delta KiB: {rss_delta_kib}/{RSS_DELTA_LIMIT_KIB}")
    return 0 if checks.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
