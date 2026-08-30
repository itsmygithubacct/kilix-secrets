#!/usr/bin/env python3
"""Socket-activation adoption path.

The event loop drains the accept queue until accept4() reports EAGAIN, so a
blocking listener stalls the single daemon thread on its second accept(). A
self-created listener sets SOCK_NONBLOCK at creation; an inherited one carries
whatever the activator chose. systemd happens to pass a non-blocking socket, so
the shipped unit hides the dependency -- these checks establish it directly
instead of relying on the activator's choice.

Deterministic by construction: no timing race, no sampling.
"""

from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import tempfile
import time


CONNECTIONS = 64
PROTOCOL_MAGIC = 0x4B534543
PROTOCOL_VERSION = 1
HEADER_BYTES = 24


class Checks:
    def __init__(self) -> None:
        self.passed = 0
        self.total = 0

    def check(self, condition: bool, label: str) -> None:
        self.total += 1
        if condition:
            self.passed += 1
        else:
            print(f"FAIL: {label}")


def request_packet(request_id: int) -> bytes:
    # Unauthorized verb; the daemon must frame a denial rather than serve it.
    return struct.pack("!IHHQII", PROTOCOL_MAGIC, PROTOCOL_VERSION, 1,
                       request_id, 0, 0)[:HEADER_BYTES].ljust(HEADER_BYTES, b"\0")


def backlog_matches_connection_bound(source: Path) -> bool:
    """The backlog must be the supported connection bound, not a literal.

    A 32-deep backlog against a documented 64-connection bound is the defect
    fixed in 9c0e61d; test_limits.py only catches it by winning a race, so
    assert the invariant at its source where it fires every run.
    """
    text = source.read_text(encoding="utf-8")
    # Capture to end of statement: the argument may carry a cast, whose own
    # ')' would truncate a naive [^)]+ match.
    calls = re.findall(r"listen\(\s*fd\s*,\s*([^;\n]+)", text)
    return len(calls) == 1 and "KSEC_MAX_CONNECTIONS" in calls[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    options = parser.parse_args()
    daemon = Path(options.build_dir).resolve() / "kilix-secretsd"
    repo = Path(__file__).resolve().parent.parent
    scratch = Path(os.environ.get("TMPDIR", ""))
    checks = Checks()

    checks.check(scratch.is_absolute() and scratch.is_dir()
                 and not scratch.is_symlink(),
                 "TMPDIR is an absolute existing non-symlink directory")
    checks.check(backlog_matches_connection_bound(repo / "src" / "daemon.c"),
                 "listen() backlog is KSEC_MAX_CONNECTIONS, not a literal")

    root = Path(tempfile.mkdtemp(prefix="ksec-activation.", dir=scratch))
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    (runtime / "kilix-secrets").mkdir(mode=0o700)
    socket_path = runtime / "kilix-secrets" / "control.sock"
    data_dir = root / "data"

    # Deliberately BLOCKING, which is what a non-systemd activator may hand over.
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    listener.setblocking(True)
    listener.bind(str(socket_path))
    listener.listen(CONNECTIONS)
    listener_fd = listener.fileno()
    os.set_inheritable(listener_fd, True)

    flags = fcntl.fcntl(listener_fd, fcntl.F_GETFL)
    checks.check(not (flags & os.O_NONBLOCK),
                 "inherited listener starts blocking, as the defect requires")

    process: subprocess.Popen[bytes] | None = None
    connections: list[socket.socket] = []
    try:
        # `exec 3<&N` puts the listener on fd 3; LISTEN_PID=$$ survives exec.
        process = subprocess.Popen(
            ["sh", "-c",
             f'exec 3<&{listener_fd}; LISTEN_PID=$$ LISTEN_FDS=1 exec "$@"',
             "sh", str(daemon), "--systemd", "--data-dir", str(data_dir)],
            pass_fds=(listener_fd,),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        checks.check(process.poll() is None,
                     "daemon adopts the inherited listener and stays running")

        # O_NONBLOCK lives on the open file description, which fork/exec/dup
        # share -- so the parent observes what the daemon set. No race.
        flags = fcntl.fcntl(listener_fd, fcntl.F_GETFL)
        checks.check(bool(flags & os.O_NONBLOCK),
                     "daemon establishes O_NONBLOCK on the inherited listener")

        # A small burst is the case that actually hangs a blocking listener:
        # the drain loop empties the queue, calls accept4() once more and
        # sleeps, so the daemon never returns to poll() to dispatch. A full
        # 64-connection burst hits the per-cycle admission cap and exits the
        # loop without that extra accept4(), which masks the defect -- so
        # exercise the small burst before the large one.
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        probe.settimeout(10.0)
        probe.connect(str(socket_path))
        connections.append(probe)
        probe.sendall(request_packet(199999))
        stalled = False
        try:
            answered = len(probe.recv(128)) >= HEADER_BYTES
        except (socket.timeout, ConnectionResetError):
            answered = False
            stalled = True
        checks.check(answered and not stalled,
                     "daemon dispatches on an existing connection after the "
                     "accept queue drains (blocking listener would stall here)")

        # The probe already holds 1 of the 64 slots, so the burst fills the
        # remaining 63; a 65th connection would be closed as overflow.
        burst: list[socket.socket] = []
        for _ in range(CONNECTIONS - 1):
            descriptor = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            descriptor.settimeout(10.0)
            descriptor.connect(str(socket_path))
            burst.append(descriptor)
            connections.append(descriptor)
        served = 0
        for index, descriptor in enumerate(burst):
            descriptor.sendall(request_packet(200000 + index))
        for descriptor in burst:
            try:
                if len(descriptor.recv(128)) >= HEADER_BYTES:
                    served += 1
            except (socket.timeout, ConnectionResetError):
                pass
        checks.check(served == CONNECTIONS - 1,
                     f"activated daemon serves {CONNECTIONS - 1}/{CONNECTIONS - 1} "
                     "burst connections without stalling the event loop")
        checks.check(process.poll() is None,
                     "daemon still responsive after the burst")
    finally:
        for descriptor in connections:
            descriptor.close()
        listener.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    print(f"activation checks: {checks.passed}/{checks.total} passed")
    return 0 if checks.passed == checks.total else 1


if __name__ == "__main__":
    raise SystemExit(main())
