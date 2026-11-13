#!/usr/bin/env python3
"""Python binding, session, watcher, and packaging-facing behavior."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
PACKAGE_PARENT = ROOT / "python"
MARKERS = Path(
    "/home/pleb/research/gpu_terminal/kilix-modules/kilix-secrets/"
    "sealed-datasets-20261113/integration"
)

APP = "kilix-secrets.test"
PEER = "kilix-secrets.peer"
READER = "kilix-secrets.reader"
PAIRING = "kilix-pairingd"
PASS_V1 = b"py-passphrase-v1"
PASS_V2 = b"py-passphrase-v2"
PASS_V3 = b"py-passphrase-v3"
SECRET_V1 = b"py-secret-value-v1"
SECRET_V2 = b"py-secret-value-v2"
IDENTITY_KEY = bytes(range(1, 33))
WRONG_ANCHOR = b"\x11" * 32
DATASET_PLAIN = b"dataset-plaintext-v1"

RESULT_TEXT = {
    0: "ok",
    1: "vault locked",
    2: "denied",
    3: "not found",
    4: "expired",
    5: "invalid input",
    6: "limit exceeded",
    7: "I/O failure",
    8: "authentication failure",
    9: "protocol failure",
    10: "busy",
    11: "already exists",
    12: "audit unavailable",
    13: "secure memory unavailable",
    14: "identity generation conflict",
    99: "unknown result",
}


class Checks:
    def __init__(self) -> None:
        self.total = 0
        self.failed = 0

    def check(self, condition: bool, message: str) -> None:
        self.total += 1
        if not condition:
            self.failed += 1
            print(f"FAIL python: {message}", file=sys.stderr)


def expect(checks: Checks, exc_type: type, message: str, fn) -> None:
    try:
        fn()
    except exc_type as exc:
        checks.check(
            str(exc) == message and int(exc.code) == int(exc_type.code),
            f"{exc_type.__name__} message {message!r}, got {exc!r} code {exc.code}",
        )
    except Exception as exc:
        checks.check(False, f"expected {exc_type.__name__}, got {type(exc).__name__}: {exc}")
    else:
        checks.check(False, f"expected {exc_type.__name__} ({message})")


def child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    previous = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(PACKAGE_PARENT) if not previous else str(PACKAGE_PARENT) + os.pathsep + previous
    )
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra:
        env.update(extra)
    return env


def _needed_sonames(library: Path) -> set[str]:
    """Dynamic NEEDED sonames. Falls back to a byte search if readelf is absent."""
    try:
        completed = subprocess.run(
            ["readelf", "-d", str(library)],
            check=False, capture_output=True, text=True,
        )
    except OSError:
        completed = None
    if completed is not None and completed.returncode == 0:
        names: set[str] = set()
        for line in completed.stdout.splitlines():
            if "NEEDED" not in line:
                continue
            start = line.find("[")
            end = line.rfind("]")
            if start >= 0 and end > start:
                names.add(line[start + 1:end])
        return names
    blob = library.read_bytes()
    return {
        name.decode("ascii")
        for name in (b"libasan.so", b"libubsan.so")
        if name in blob
    }


def _compiler_runtime(filename: str) -> str | None:
    try:
        completed = subprocess.run(
            ["cc", f"-print-file-name={filename}"],
            check=False, capture_output=True, text=True,
        )
    except OSError:
        return None
    path = completed.stdout.strip()
    if completed.returncode != 0 or not path or path == filename:
        return None
    if not Path(path).is_file():
        return None
    return path


def _runtime_loaded(soname_prefix: str) -> bool:
    try:
        maps = Path("/proc/self/maps").read_text(encoding="ascii", errors="replace")
    except OSError:
        return False
    return soname_prefix in maps


def _with_leak_detection_off(options: str) -> str:
    parts = [part for part in options.split(":") if part]
    if any(part.split("=", 1)[0] == "detect_leaks" for part in parts):
        return ":".join(parts)
    parts.append("detect_leaks=0")
    return ":".join(parts)


def _delegate_sanitizer_preload(library: Path, argv: list[str]) -> int | None:
    """Run the checks in a child when the library was built with ASan.

    An instrumented ``libkilix-secrets.so.0`` aborts if ctypes loads it into
    a CPython that did not load ``libasan`` first. Leak detection stays off
    because CPython leaks at exit; every other sanitizer check stays on.
    Returns the child status, or None when this process should run the checks.
    """
    if not library.is_file() or _runtime_loaded("libasan.so"):
        return None
    needed = _needed_sonames(library)
    if not any(name == "libasan.so" or name.startswith("libasan.so.") for name in needed):
        return None
    preload: list[str] = []
    asan = _compiler_runtime("libasan.so")
    if asan is None:
        print("libasan.so was not found", file=sys.stderr)
        return 2
    preload.append(asan)
    if any(name == "libubsan.so" or name.startswith("libubsan.so.") for name in needed):
        ubsan = _compiler_runtime("libubsan.so")
        if ubsan is None:
            print("libubsan.so was not found", file=sys.stderr)
            return 2
        preload.append(ubsan)
    env = os.environ.copy()
    existing = env.get("LD_PRELOAD", "")
    env["LD_PRELOAD"] = ":".join(preload + ([existing] if existing else []))
    env["ASAN_OPTIONS"] = _with_leak_detection_off(env.get("ASAN_OPTIONS", ""))
    completed = subprocess.run([sys.executable, *argv], env=env)
    return int(completed.returncode)


def _process_environment(pid: int) -> dict[str, str] | None:
    try:
        raw = Path(f"/proc/{pid}/environ").read_bytes()
    except OSError:
        return None
    parsed: dict[str, str] = {}
    for item in raw.split(b"\0"):
        if b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        parsed[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
    return parsed


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


def start_daemon(daemon: Path, socket_path: Path, data_dir: Path) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [str(daemon), "--socket", str(socket_path), "--data-dir", str(data_dir),
         "--development-kdf-ops", "3", "--development-kdf-mem-mib", "256",
         "--idle-seconds", "300"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        close_fds=True,
    )
    if not wait_for_socket(socket_path, process):
        process.kill()
        process.wait(timeout=5)
        error = process.stderr.read() if process.stderr is not None else b""
        raise RuntimeError(f"daemon did not create socket (stderr={error!r})")
    return process


def stop_daemon(process: subprocess.Popen[bytes] | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if process.stderr is not None:
        process.stderr.close()


def kill_pid(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.02)


def note(value: bytes, expires: int = 0):
    from kilix_secrets import Field, Record
    return Record(
        owner=APP, type="note", label="py-label", expires_at=expires,
        fields=[Field("secret", value)],
    )


def doctor_lines(checks: Checks, body: bytes, expected: dict[str, str], label: str) -> None:
    text = body.decode("ascii")
    lines = text.splitlines()
    checks.check(text.endswith("\n") and lines[0] == "format=1", f"{label} starts with format=1")
    for key, value in expected.items():
        checks.check(f"{key}={value}" in lines, f"{label} has {key}={value}")
    for key, value in {
        "storage": "readable",
        "kdf_point": "development:ops=3,mem=256MiB",
        "torn_tail": "no",
        "audit": "available",
        "session_monitor": "active",
    }.items():
        checks.check(f"{key}={value}" in lines, f"{label} has {key}={value}")
    checks.check(
        re.fullmatch(r"graphical_sessions=[0-9]+/64", lines[-1]) is not None,
        f"{label} graphical_sessions line is {lines[-1]!r}",
    )


def show_text(record_id: bytes, revision: int, grants: str) -> bytes:
    ident = record_id.hex()
    return (
        f"id={ident}\n"
        f"owner={APP}\n"
        "type=note\n"
        "label=py-label\n"
        f"revision={revision}\n"
        "expires_at=0\n"
        "expired=no\n"
        "fields=1/8\n"
        "field=secret\n"
        f"{grants}"
    ).encode("ascii")


def list_line(record_id: bytes, expires: int = 0) -> bytes:
    return f"{record_id.hex()}\tnote\tpy-label\t{expires}\n".encode("ascii")


def run_role(argv: list[str]) -> int:
    kind = argv[0]
    sys.path.insert(0, str(PACKAGE_PARENT))
    if kind == "library-bad":
        from kilix_secrets import load_library
        load_library()
        return 0
    if kind == "library-soname":
        from kilix_secrets import result_string
        sys.stdout.write(result_string(0))
        return 0
    if kind == "connect":
        from kilix_secrets import connect
        from kilix_secrets._protocol import recv_frame
        held = socket.socket(fileno=int(os.environ["KSEC_DIRECT_FD"]))
        message, fds = recv_frame(held)
        os.environ["XDG_RUNTIME_DIR"] = message["runtime"]
        os.environ["KILIX_SECRETS_SOCKET"] = message["socket"]
        os.environ["KILIX_SECRETS_CAP_FD"] = str(fds[0])
        client = connect()
        try:
            body = client.doctor()
        finally:
            client.close()
        sys.stdout.buffer.write(body.splitlines()[0] + b"\n")
        return 0
    if kind == "get-fd":
        from kilix_secrets import Client
        from kilix_secrets._protocol import recv_frame
        held = socket.socket(fileno=int(os.environ["KSEC_DIRECT_FD"]))
        message, fds = recv_frame(held)
        client = Client.connect_at(message["socket"], fds[0])
        try:
            out = os.memfd_create("ksec-get", os.MFD_CLOEXEC)
            client.get_to_fd(bytes.fromhex(argv[1]), "secret", out)
            os.lseek(out, 0, os.SEEK_SET)
            sys.stdout.buffer.write(os.read(out, 256))
            os.close(out)
        finally:
            client.close()
        return 0
    if kind == "parent-holder":
        from kilix_secrets import Verb
        from kilix_secrets._session import Worker
        worker = Worker()
        worker.start(argv[1], APP, Verb.ALL, 60, None)
        print(worker.pid, flush=True)
        time.sleep(30)
        worker.close()
        return 0
    if kind == "seal-slow":
        from kilix_secrets import seal_file
        source, target = argv[1], argv[2]

        class Slow:
            def seal_fd(self, record_id, name, revision, in_fd, out_fd) -> None:
                del record_id, name, revision
                payload = os.read(in_fd, 64)
                for index in range(len(payload)):
                    os.write(out_fd, payload[index:index + 1])
                    time.sleep(0.4)

        seal_file(Slow(), b"\x22" * 16, "py-notes", 1, source, target)
        return 0
    sys.stderr.write(f"unknown role {kind}\n")
    return 2


def test_library(checks: Checks, library: Path) -> None:
    from kilix_secrets import (
        AuditError, Busy, Conflict, CryptoError, Denied, Exists, Expired,
        Invalid, IoError, LimitExceeded, Locked, NotFound, OutOfMemory,
        ProtocolError, Result, Slot, Status, Verb, load_library, raise_for_result,
        result_string,
    )
    classes = {
        1: Locked, 2: Denied, 3: NotFound, 4: Expired, 5: Invalid,
        6: LimitExceeded, 7: IoError, 8: CryptoError, 9: ProtocolError,
        10: Busy, 11: Exists, 12: AuditError, 13: OutOfMemory, 14: Conflict,
    }
    checks.check(Result.LOCKED == 1 and Result.CONFLICT == 14 and Verb.ALL == 127, "result and verb values")
    checks.check(Slot.PASSPHRASE == 1 and Slot.RECOVERY == 2, "slot values")
    checks.check(Status.INITIALIZED == 1 and Status.RECOVERY_CONFIRMED == 2
                 and Status.UNLOCKED == 4, "status flag values")
    for code, text in RESULT_TEXT.items():
        checks.check(result_string(code) == text, f"result_string({code}) is {text!r}")
    for code, exc_type in classes.items():
        expect(checks, exc_type, RESULT_TEXT[code], lambda code=code: raise_for_result(code))

    bad = subprocess.run(
        [sys.executable, __file__, "--role", "library-bad"],
        check=False, capture_output=True, text=True,
        env=child_env({"KILIX_SECRETS_LIBRARY": __file__}),
    )
    checks.check(bad.returncode != 0 and "OSError" in bad.stderr and bad.stdout == "",
                 "a set library path does not fall through when it cannot be loaded")
    soname_env = child_env({"LD_LIBRARY_PATH": str(library.parent)})
    soname_env.pop("KILIX_SECRETS_LIBRARY", None)
    soname = subprocess.run(
        [sys.executable, __file__, "--role", "library-soname"],
        check=False, capture_output=True, text=True, env=soname_env,
    )
    checks.check(soname.returncode == 0 and soname.stdout == "ok",
                 "unset library path loads libkilix-secrets.so.0")
    os.environ["KILIX_SECRETS_LIBRARY"] = __file__
    try:
        load_library()
    except OSError:
        failed = True
    else:
        failed = False
    checks.check(failed, "changing the library path to a non-library raises OSError")
    os.environ["KILIX_SECRETS_LIBRARY"] = str(library)
    checks.check(result_string(0) == "ok", "restoring the library path loads it again")


def test_seal_files(checks: Checks, root: Path) -> None:
    from kilix_secrets import CryptoError, seal_file, unseal_file
    directory = root / "seal"
    directory.mkdir(mode=0o700)
    source = directory / "source"
    source.write_bytes(b"PLAINTEXT")
    source.chmod(0o600)
    target = directory / "target"
    target.write_bytes(b"OLD-TARGET-BYTES!!")
    target.chmod(0o600)
    held: list[subprocess.Popen[bytes]] = []
    try:
        killer = subprocess.Popen(
            [sys.executable, __file__, "--role", "seal-slow", str(source), str(target)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            env=child_env(),
        )
        held.append(killer)
        time.sleep(0.3)
        killer.send_signal(signal.SIGKILL)
        finished = killer.wait(timeout=5)
        names = set(os.listdir(directory))
        checks.check(finished == -signal.SIGKILL, f"seal child died from SIGKILL ({finished})")
        checks.check(target.read_bytes() == b"OLD-TARGET-BYTES!!",
                     "killed seal_file leaves the old target bytes")
        checks.check(names == {"source", "target"},
                     f"killed seal_file leaves no temporary ({sorted(names)})")
        for name in names:
            blob = (directory / name).read_bytes()
            if name != "source":
                checks.check(b"PLAINTEXT" not in blob, f"{name} contains plaintext after SIGKILL")

        class Boom:
            def seal_fd(self, record_id, name, revision, in_fd, out_fd) -> None:
                del record_id, name, revision, in_fd
                os.write(out_fd, b"PARTIAL")
                raise CryptoError("authentication failure")

        expect(checks, CryptoError, "authentication failure",
               lambda: seal_file(Boom(), b"\x22" * 16, "py-notes", 1, str(source), str(target)))
        checks.check(target.read_bytes() == b"OLD-TARGET-BYTES!!", "failed seal_file leaves the target")
        checks.check(set(os.listdir(directory)) == {"source", "target"},
                     "failed seal_file leaves no temporary")

        class Copy:
            def seal_fd(self, record_id, name, revision, in_fd, out_fd) -> None:
                del record_id, name, revision
                os.write(out_fd, os.read(in_fd, 64))

            def unseal_fd(self, record_id, name, in_fd, out_fd) -> int:
                del record_id, name
                os.write(out_fd, os.read(in_fd, 64))
                return 7

        fresh = directory / "fresh"
        seal_file(Copy(), b"\x22" * 16, "py-notes", 1, str(source), str(fresh))
        mode = stat.S_IMODE(fresh.stat().st_mode)
        checks.check(fresh.read_bytes() == b"PLAINTEXT" and mode == 0o600,
                     "seal_file publishes the source bytes as mode 0600")
        opened = unseal_file(Copy(), b"\x22" * 16, "py-notes", str(fresh), str(target))
        checks.check(opened == 7 and target.read_bytes() == b"PLAINTEXT"
                     and stat.S_IMODE(target.stat().st_mode) == 0o600,
                     "unseal_file publishes plaintext and returns revision 7")

        outside_dir = root / "outside"
        outside_dir.mkdir(mode=0o700)
        outside = outside_dir / "referent"
        outside.write_bytes(b"OUTSIDE-UNTOUCHED!!!!")
        outside.chmod(0o600)
        link = directory / "linked"
        link.symlink_to(outside)
        seal_file(Copy(), b"\x22" * 16, "py-notes", 1, str(source), str(link))
        checks.check(outside.read_bytes() == b"OUTSIDE-UNTOUCHED!!!!",
                     "seal_file does not write through a symlink")
        checks.check(link.is_file() and not link.is_symlink() and link.read_bytes() == b"PLAINTEXT",
                     "seal_file replaces a symlink with the published file")
    finally:
        for process in held:
            if process.poll() is None and process.pid is not None:
                kill_pid(process.pid)


def test_worker_thread_lifetime(checks: Checks, socket_path: Path) -> None:
    """A worker survives the thread that created the session."""
    from kilix_secrets import Session, Verb
    holder: dict[str, object] = {}

    def create() -> None:
        try:
            created = Session(str(socket_path), APP, Verb.ALL, 300)
            holder["session"] = created
            holder["pid"] = created.worker_pid
            holder["status"] = created.status()
        except Exception as exc:
            holder["error"] = exc

    creator = threading.Thread(target=create)
    creator.start()
    creator.join(10)
    session = holder.get("session")
    if not isinstance(session, Session) or "error" in holder:
        checks.check(False, f"short-lived thread created a session ({holder.get('error')})")
        checks.check(False, "new thread keeps the same worker")
        if isinstance(session, Session):
            session.close()
        return
    pid = holder.get("pid")
    first = holder.get("status")
    time.sleep(0.5)
    main_error: Exception | None = None
    again: int | None = None
    main_pid: int | None = None
    try:
        again = session.status()
        main_pid = session.worker_pid
    except Exception as exc:
        main_error = exc
    later: dict[str, object] = {}

    def call() -> None:
        try:
            later["status"] = session.status()
            later["pid"] = session.worker_pid
        except Exception as exc:
            later["error"] = exc

    try:
        caller = threading.Thread(target=call)
        caller.start()
        caller.join(10)
        checks.check(
            main_error is None and again == first and main_pid == pid and pid is not None,
            f"main thread keeps worker {pid} after the creator exits "
            f"({main_pid}, {again}, {main_error})",
        )
        checks.check(
            "error" not in later and later.get("status") == first and later.get("pid") == pid,
            f"new thread keeps worker {pid} ({later.get('pid')}, {later.get('status')}, "
            f"{later.get('error')})",
        )
    finally:
        session.close()


def test_worker(checks: Checks, socket_path: Path) -> None:
    from kilix_secrets import Verb
    from kilix_secrets._protocol import close_fds
    from kilix_secrets._session import Worker
    worker = Worker()
    worker.start(str(socket_path), APP, Verb.ALL, 30, None)
    try:
        worker_env = _process_environment(worker.pid or 0)
        checks.check(
            worker_env is not None
            and worker_env.get("LD_PRELOAD", "") == os.environ.get("LD_PRELOAD", "")
            and worker_env.get("ASAN_OPTIONS", "") == os.environ.get("ASAN_OPTIONS", ""),
            "worker inherits LD_PRELOAD and ASAN_OPTIONS",
        )
        refused, fds = worker.request("nope", {}, [])
        close_fds(fds)
        checks.check(refused.get("ok") is False and refused.get("code") == 5
                     and refused.get("message") == "unknown method",
                     f"worker refuses an unknown method ({refused})")
        followed, fds = worker.request("result_string", {"code": 0}, [])
        close_fds(fds)
        checks.check(followed.get("ok") is True and followed.get("text") == "ok",
                     "worker stays up after refusing a method")
    finally:
        worker.close()

    test_worker_thread_lifetime(checks, socket_path)

    holder = subprocess.Popen(
        [sys.executable, __file__, "--role", "parent-holder", str(socket_path)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=child_env(),
    )
    worker_pid = 0
    try:
        assert holder.stdout is not None
        deadline = time.monotonic() + 10
        line = b""
        while time.monotonic() < deadline:
            if holder.poll() is not None:
                break
            ready, _, _ = __import__("select").select([holder.stdout], [], [], 0.2)
            if ready:
                line = holder.stdout.readline()
                break
        worker_pid = int(line)
        kill_pid(holder.pid)
        gone = False
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(worker_pid, 0)
            except ProcessLookupError:
                gone = True
                break
            time.sleep(0.05)
        checks.check(gone, "worker exits when its parent is killed")
    finally:
        if holder.poll() is None and holder.pid is not None:
            kill_pid(holder.pid)
        if worker_pid:
            try:
                os.kill(worker_pid, 0)
            except ProcessLookupError:
                pass
            else:
                kill_pid(worker_pid)


def test_connect_env(checks: Checks, socket_path: Path, runtime: Path) -> None:
    from kilix_secrets import Verb, mint_for_child
    from kilix_secrets._protocol import send_frame
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    child_fd = child.detach()
    connected = subprocess.Popen(
        [sys.executable, __file__, "--role", "connect"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=child_env({"KSEC_DIRECT_FD": str(child_fd)}),
        pass_fds=(child_fd,),
    )
    os.close(child_fd)
    try:
        cap = mint_for_child(str(socket_path), connected.pid, APP, Verb.DOCTOR, 30)
        try:
            send_frame(parent, {
                "socket": str(socket_path),
                "runtime": str(runtime),
            }, [cap])
        finally:
            os.close(cap)
        parent.close()
        stdout, stderr = connected.communicate(timeout=30)
    except Exception:
        if connected.poll() is None and connected.pid is not None:
            kill_pid(connected.pid)
        raise
    checks.check(connected.returncode == 0 and stdout == b"format=1\n",
                 f"connect() via the environment reads doctor ({stderr!r})")


def test_get_fd(checks: Checks, socket_path: Path, record_id: bytes) -> None:
    from kilix_secrets import Verb, mint_for_child
    from kilix_secrets._protocol import send_frame
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    child_fd = child.detach()
    proc = subprocess.Popen(
        [sys.executable, __file__, "--role", "get-fd", record_id.hex()],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=child_env({"KSEC_DIRECT_FD": str(child_fd)}),
        pass_fds=(child_fd,),
    )
    os.close(child_fd)
    try:
        cap = mint_for_child(str(socket_path), proc.pid, APP, Verb.ALL, 30)
        try:
            send_frame(parent, {"socket": str(socket_path)}, [cap])
        finally:
            os.close(cap)
        parent.close()
        stdout, stderr = proc.communicate(timeout=30)
    except Exception:
        if proc.poll() is None and proc.pid is not None:
            kill_pid(proc.pid)
        raise
    checks.check(proc.returncode == 0 and stdout == SECRET_V2,
                 f"Client.get_to_fd returns the secret ({stderr!r} {stdout!r})")


def test_vault(checks: Checks, socket_path: Path) -> None:
    from kilix_secrets import (
        Busy, Conflict, CryptoError, Denied, Exists, Expired, Field, IdentityOpen,
        Invalid, LimitExceeded, Locked, NotFound, ProtocolError, Record, Session,
        Slot, Status, Verb, Watcher, mint_for_child, zero,
    )
    need_l2 = (MARKERS / "MERGED-L2").is_file()
    need_l3 = (MARKERS / "MERGED-L3").is_file()
    session = Session(str(socket_path), APP, Verb.ALL, 300)
    peer = None
    reader = None
    pairing = None
    short = None
    watcher = None
    try:
        argv = Path(f"/proc/{session.worker_pid}/cmdline").read_bytes().split(b"\0")
        checks.check(argv[1:3] == [b"-m", b"kilix_secrets.worker"],
                     "session worker is python -m kilix_secrets.worker")
        expect(checks, Denied, "denied",
               lambda: mint_for_child(str(socket_path), os.getpid(), APP, Verb.ALL, 30))
        doctor_lines(checks, session.doctor(), {
            "initialized": "no", "state": "locked", "recovery": "not-initialized",
            "records": "0/1024", "identity_leases": "0/128",
        }, "doctor before init")
        checks.check(session.result_string(0) == "ok", "session result_string(0) is ok")
        recovery = session.vault_init(PASS_V1)
        checks.check(re.fullmatch(rb"[0-9a-f]{64}", bytes(recovery)) is not None,
                     "vault_init returns 64 lowercase hex bytes")
        expect(checks, Denied, "denied", lambda: session.unlock(Slot.PASSPHRASE, PASS_V1))
        expect(checks, Invalid, "invalid input", lambda: session.unlock(9, PASS_V1))
        expect(checks, CryptoError, "authentication failure",
               lambda: session.unlock(Slot.RECOVERY, b"ab" * 32))
        # The first backoff is one second. A development KDF can finish on
        # either side of it. Exactly one of these checks runs, so the count
        # does not depend on that race.
        try:
            session.unlock(Slot.RECOVERY, bytes(recovery))
        except Busy as exc:
            checks.check(str(exc) == "busy" and exc.code == 10,
                         "unlock during backoff is busy")
            time.sleep(1.2)
            session.unlock(Slot.RECOVERY, bytes(recovery))
        else:
            checks.check(True, "recovery unlock is accepted")
        expect(checks, Exists, "already exists", lambda: session.vault_init(PASS_V1))
        expect(checks, Exists, "already exists",
               lambda: session.unlock(Slot.PASSPHRASE, PASS_V1))
        doctor_lines(checks, session.doctor(), {
            "initialized": "yes", "state": "unlocked", "recovery": "confirmed",
            "records": "0/1024", "identity_leases": "0/128",
        }, "doctor after recovery unlock")
        expect(checks, Invalid, "field value is empty",
               lambda: session.put(Record(
                   owner=APP, type="note", label="py-label",
                   fields=[Field("secret", b"")])))
        expect(checks, Denied, "denied",
               lambda: session.put(Record(
                   owner=PEER, type="note", label="py-label",
                   fields=[Field("secret", SECRET_V1)])))
        record_id = session.put(note(SECRET_V1))
        checks.check(len(record_id) == 16, "put returns a 16-byte record id")
        got = session.get(record_id, "secret")
        checks.check(type(got) is bytearray and got == SECRET_V1, "get returns the stored secret")
        zero(got)
        checks.check(got == bytearray(len(SECRET_V1)), "zero wipes the returned secret")
        expect(checks, NotFound, "not found", lambda: session.get(record_id, "missing"))
        expect(checks, LimitExceeded, "limit exceeded",
               lambda: session.get(record_id, "secret", max_len=4))
        session.replace(record_id, note(SECRET_V2))
        replaced = session.get(record_id, "secret")
        checks.check(replaced == SECRET_V2, "replace then get returns py-secret-value-v2")
        zero(replaced)
        listing = list_line(record_id)
        checks.check(session.list() == listing, "list is the one stored record")
        checks.check(session.show(record_id) == show_text(record_id, 2, "grants=0/16\n"),
                     "show after replace is revision 2 with no grants")
        test_get_fd(checks, socket_path, record_id)
        short = Session(str(socket_path), APP, Verb.ALL, lifetime=2)
        time.sleep(3.2)
        checks.check(short.list() == listing, "session list survives a 2-second capability")
        short.close()
        short = None
        found: list[bytes] = []
        errors: list[BaseException] = []

        def listed() -> None:
            try:
                found.append(session.list())
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=listed) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        checks.check(errors == [] and found == [listing, listing, listing, listing],
                     "four threads observe the same list")
        session.grant(record_id, PEER, Verb.READ | Verb.LIST_OWN | Verb.USE)
        checks.check(
            session.show(record_id) == show_text(
                record_id, 3, "grants=1/16\ngrant=kilix-secrets.peer\tverbs=read,list-own,use\n"),
            "show after grant is revision 3 with read,list-own,use",
        )
        peer = Session(str(socket_path), PEER, Verb.READ | Verb.LIST_OWN | Verb.USE, 60)
        peer_got = peer.get(record_id, "secret")
        checks.check(peer_got == SECRET_V2 and peer.list() == listing, "grantee reads and lists")
        zero(peer_got)
        expect(checks, Exists, "already exists",
               lambda: session.grant(record_id, PEER, Verb.READ | Verb.LIST_OWN | Verb.USE))
        expect(checks, Invalid, "invalid input",
               lambda: session.grant(record_id, PEER, Verb.CREATE))
        session.revoke(record_id, PEER)
        checks.check(session.show(record_id) == show_text(record_id, 4, "grants=0/16\n"),
                     "show after revoke is revision 4 with no grants")
        expect(checks, Denied, "denied", lambda: peer.get(record_id, "secret"))
        expect(checks, NotFound, "not found", lambda: session.revoke(record_id, PEER))
        peer.close()
        peer = None
        expired_id = session.put(note(SECRET_V1, expires=1))
        expect(checks, Expired, "expired", lambda: session.get(expired_id, "secret"))
        checks.check(session.list() == listing + list_line(expired_id, 1),
                     "list contains the live record and the expired record")
        session.delete(expired_id)
        session.delete(record_id)
        checks.check(session.list() == b"\n", "list of no records is one newline")
        expect(checks, NotFound, "not found", lambda: session.show(record_id))
        expect(checks, NotFound, "not found", lambda: session.delete(record_id))
        session.compact()
        session.lock()
        expect(checks, Locked, "vault locked", lambda: session.list())
        expect(checks, Locked, "vault locked", lambda: session.compact())
        expect(checks, LimitExceeded, "descriptor exceeds the accepted size",
               lambda: session.unlock(Slot.PASSPHRASE, b"x" * 1025))
        expect(checks, Invalid, "invalid input",
               lambda: session.unlock(Slot.PASSPHRASE, b"short"))
        session.unlock(Slot.PASSPHRASE, PASS_V1)
        pairing = Session(str(socket_path), PAIRING, Verb.ALL, 60)
        ident = pairing.put(Record(
            owner=PAIRING, type="device-identity", label="py-device", expires_at=0,
            fields=[Field("private-key", IDENTITY_KEY)],
        ))
        expect(checks, Denied, "denied", lambda: pairing.get(ident, "private-key"))
        expect(checks, Conflict, "identity generation conflict",
               lambda: pairing.identity_open(ident, WRONG_ANCHOR))
        opened = pairing.identity_open(ident)
        try:
            blocked = False
            try:
                os.read(opened.lease_fd, 1)
            except BlockingIOError:
                blocked = True
            checks.check(isinstance(opened, IdentityOpen), "identity_open returns IdentityOpen")
            checks.check(opened.private_key == bytearray(IDENTITY_KEY),
                         "identity_open returns the private key")
            checks.check(opened.info.version == 1, "identity_open version is 1")
            checks.check(opened.info.record_id == ident, "identity_open record id matches")
            # Revisions are one vault-wide counter. The note used 1 through 7.
            checks.check(opened.info.record_revision == 8,
                         f"identity_open revision is 8 ({opened.info.record_revision})")
            checks.check(blocked, "identity lease read is nonblocking while the lease is held")
        finally:
            opened.close()
            checks.check(opened.private_key == bytearray(32), "identity_open.close wipes the key")
        info = pairing.identity_info(ident)
        checks.check(info.version == 1, "identity_info version is 1")
        checks.check(info.record_id == ident, "identity_info record id matches")
        checks.check(info.record_revision == 8,
                     f"identity_info revision is 8 ({info.record_revision})")
        ordinary = pairing.put(Record(
            owner=PAIRING, type="note", label="py-label",
            fields=[Field("secret", SECRET_V1)],
        ))
        expect(checks, Invalid, "invalid input", lambda: pairing.identity_open(ordinary))
        pairing.delete(ordinary)
        pairing.delete(ident)
        pairing.close()
        pairing = None
        reader = Session(str(socket_path), READER, Verb.READ, 60)
        expect(checks, Denied, "denied", lambda: reader.put(note(SECRET_V1)))
        expect(checks, Denied, "denied", lambda: reader.doctor())
        expect(checks, Denied, "denied",
               lambda: reader.rotate_master(PASS_V1, recovery))
        expect(checks, Invalid, "invalid input", lambda: session.change_passphrase(b"short"))
        session.change_passphrase(PASS_V2)
        session.rotate_master(PASS_V2, bytes(recovery))
        reader.close()
        reader = None
        backup_dir = socket_path.parent.parent.parent / "backups"
        backup_dir.mkdir(mode=0o700, exist_ok=True)
        restored_id = session.put(note(SECRET_V2))
        loose = backup_dir / "loose.ksb"
        loose.write_bytes(b"")
        loose.chmod(0o644)
        expect(checks, Denied, "denied", lambda: session.export_backup(PASS_V2, str(loose)))
        occupied = backup_dir / "occupied.ksb"
        occupied_fd = os.open(str(occupied), os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.write(occupied_fd, b"x")
        os.close(occupied_fd)
        expect(checks, Exists, "already exists",
               lambda: session.export_backup(PASS_V2, str(occupied)))
        backup = backup_dir / "vault.ksb"
        made = os.open(str(backup), os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(made)
        session.export_backup(PASS_V2, str(backup))
        checks.check(stat.S_IMODE(backup.stat().st_mode) == 0o600 and backup.stat().st_size >= 192,
                     "export writes a mode-0600 backup of at least 192 bytes")
        session.delete(restored_id)
        checks.check(session.list() == b"\n", "deleted record is absent before import")
        tiny = backup_dir / "tiny.ksb"
        tiny_fd = os.open(str(tiny), os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.write(tiny_fd, b"x" * 10)
        os.close(tiny_fd)
        expect(checks, LimitExceeded, "limit exceeded",
               lambda: session.import_backup(PASS_V2, str(tiny)))
        session.import_backup(PASS_V2, str(backup))
        session.unlock(Slot.PASSPHRASE, PASS_V2)
        imported = session.list()
        checks.check(imported == list_line(restored_id), "import restores the exported record")
        imported_secret = session.get(restored_id, "secret")
        checks.check(imported_secret == SECRET_V2, "import restores py-secret-value-v2")
        zero(imported_secret)

        if need_l2:
            test_datasets(checks, session)
        else:
            expect(checks, ProtocolError, "protocol failure",
                   lambda: session.dataset_create("py-dataset"))
        if need_l3:
            checks.check(session.status() == 7,
                         "status is initialized, recovery-confirmed, and unlocked")
            watcher = test_watcher(checks, socket_path, session)
        else:
            expect(checks, ProtocolError, "protocol failure", lambda: session.status())
        expect(checks, Invalid, "invalid input",
               lambda: session.reset_vault("RESET-VAULT-WITHOUT-IDENTITY-LOSS", PASS_V3))
        new_recovery = session.reset_vault("RESET-VAULT-AND-LOSE-IDENTITY", PASS_V3)
        checks.check(re.fullmatch(rb"[0-9a-f]{64}", bytes(new_recovery)) is not None,
                     "reset returns 64 lowercase hex bytes")
        zero(new_recovery)
        expect(checks, Locked, "vault locked", lambda: session.list())
        zero(recovery)
    finally:
        for item in (watcher, short, peer, reader, pairing, session):
            if item is not None:
                item.close()


def _rejected_seal_arguments(checks: Checks, session, record_id: bytes, root: Path) -> None:
    from kilix_secrets import Invalid
    arg_src = root / "arg-src"
    arg_src.write_bytes(b"ARG-PLAIN")
    arg_src.chmod(0o600)
    arg_out = root / "arg-out"
    arg_out.write_bytes(b"")
    arg_out.chmod(0o600)
    src_fd = os.open(arg_src, os.O_RDONLY | os.O_CLOEXEC)
    out_fd = os.open(arg_out, os.O_RDWR | os.O_CLOEXEC)
    try:
        expect(checks, Invalid, "text contains a NUL",
               lambda: session.seal_fd(record_id, "book\x00evil", 1, src_fd, out_fd))
        expect(checks, Invalid, "revision is out of range",
               lambda: session.seal_fd(record_id, "book", -1, src_fd, out_fd))
        expect(checks, Invalid, "revision is out of range",
               lambda: session.seal_fd(record_id, "book", 2**64, src_fd, out_fd))
        expect(checks, Invalid, "text contains a NUL",
               lambda: session.dataset_create("py\x00dataset"))
    finally:
        os.close(src_fd)
        os.close(out_fd)
    checks.check(arg_out.stat().st_size == 0, "rejected seal arguments write nothing")


def _write_paused(write_fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    half = len(view) // 2
    off = 0
    try:
        while off < half:
            off += os.write(write_fd, view[off:half])
        time.sleep(2.5)
        while off < len(view):
            off += os.write(write_fd, view[off:])
    finally:
        os.close(write_fd)
        view.release()


def _expiring_seal_round_trip(checks: Checks, session, record_id: bytes, root: Path) -> None:
    from kilix_secrets import Session, Verb, seal_file, unseal_file
    pipe_plain = b"retry-pipe-" + os.urandom(64 * 1024)
    short = Session(session._socket_path, APP, Verb.ALL, lifetime=2)
    read_fd, write_fd = os.pipe()
    sealed_path = root / "retry-pipe.sealed"
    plain_path = root / "retry-pipe.plain"
    writer = threading.Thread(target=_write_paused, args=(write_fd, pipe_plain))
    writer.start()
    out = os.open(sealed_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    ok = False
    detail = "no result"
    try:
        try:
            short.seal_fd(record_id, "retry-pipe", 7, read_fd, out)
        except Exception as exc:
            detail = f"raised {type(exc).__name__}: {exc}"
        else:
            os.close(out)
            out = -1
            os.close(read_fd)
            read_fd = -1
            writer.join(timeout=5)
            rev = session.unseal_file(
                record_id, "retry-pipe", str(sealed_path), str(plain_path))
            got = plain_path.read_bytes()
            ok = rev == 7 and got == pipe_plain
            detail = f"revision {rev} unsealed {len(got)} of {len(pipe_plain)}"
    finally:
        if out >= 0:
            os.close(out)
        if read_fd >= 0:
            os.close(read_fd)
        short.close()
        writer.join(timeout=5)
    checks.check(ok, f"expiring seal_fd round-trips the pipe plaintext ({detail})")

    file_plain = b"retry-file-" + os.urandom(32 * 1024)
    fifo = root / "retry.fifo"
    os.mkfifo(fifo, 0o600)
    target = root / "retry-file.sealed"
    opened = root / "retry-file.plain"
    file_session = Session(session._socket_path, APP, Verb.ALL, lifetime=2)

    def produce() -> None:
        fd = os.open(fifo, os.O_WRONLY)
        _write_paused(fd, file_plain)

    producer = threading.Thread(target=produce)
    producer.start()
    ok = False
    detail = "no result"
    try:
        try:
            seal_file(file_session, record_id, "retry-file", 3, str(fifo), str(target))
        except Exception as exc:
            detail = f"raised {type(exc).__name__}: {exc}"
        else:
            rev = unseal_file(session, record_id, "retry-file", str(target), str(opened))
            got = opened.read_bytes()
            ok = rev == 3 and got == file_plain
            detail = f"revision {rev} unsealed {len(got)} of {len(file_plain)}"
    finally:
        file_session.close()
        if producer.is_alive():
            try:
                dummy = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
                os.close(dummy)
            except OSError:
                pass
        producer.join(timeout=5)
    checks.check(ok, f"expiring seal_file round-trips the fifo plaintext ({detail})")


def test_datasets(checks: Checks, session) -> None:
    from kilix_secrets import Denied, NotFound, Verb, Session
    record_id = session.dataset_create("py-dataset")
    checks.check(len(record_id) == 16, "dataset_create returns a 16-byte id")
    shown = session.show(record_id).decode("ascii")
    for line in (
        f"id={record_id.hex()}",
        f"owner={APP}",
        "type=dataset-key",
        "label=py-dataset",
        "expires_at=0",
        "expired=no",
        "fields=1/8",
        "field=dataset-key",
        "grants=0/16",
    ):
        checks.check(line in shown.splitlines(), f"dataset show has {line}")
    expect(checks, Denied, "denied", lambda: session.get(record_id, "dataset-key"))
    root = Path(tempfile.mkdtemp(prefix="ksec-dataset.", dir=os.environ["TMPDIR"]))
    try:
        source = root / "plain"
        source.write_bytes(DATASET_PLAIN)
        source.chmod(0o600)
        sealed = root / "sealed"
        opened = root / "opened"
        session.seal_file(record_id, "py-notes", 1, str(source), str(sealed))
        checks.check(stat.S_IMODE(sealed.stat().st_mode) == 0o600 and sealed.stat().st_size > 0,
                     "seal_file writes a mode-0600 sealed file")
        revision = session.unseal_file(record_id, "py-notes", str(sealed), str(opened))
        checks.check(revision == 1 and opened.read_bytes() == DATASET_PLAIN
                     and stat.S_IMODE(opened.stat().st_mode) == 0o600,
                     "unseal_file returns revision 1 and the plaintext")
        reader = Session(session._socket_path, READER, Verb.READ, 60)
        try:
            other = root / "denied"
            expect(checks, Denied, "denied",
                   lambda: reader.seal_file(record_id, "py-notes", 1, str(source), str(other)))
        finally:
            reader.close()
        _rejected_seal_arguments(checks, session, record_id, root)
        _expiring_seal_round_trip(checks, session, record_id, root)
        session.delete(record_id)
        missing = root / "missing"
        expect(checks, NotFound, "not found",
               lambda: session.unseal_file(record_id, "py-notes", str(sealed), str(missing)))
    finally:
        if root.name.startswith("ksec-dataset.") and root.parent == Path(os.environ["TMPDIR"]):
            import shutil
            shutil.rmtree(root)


def test_watcher(checks: Checks, socket_path, session):
    from kilix_secrets import Watcher
    seen: list[int] = []
    watcher = Watcher(str(socket_path), APP, seen.append, lifetime=2)
    try:
        deadline = time.monotonic() + 6
        while watcher.renewals < 3 and time.monotonic() < deadline:
            time.sleep(0.05)
        checks.check(watcher.renewals >= 3 and seen == [] and watcher.error is None,
                     f"watcher renews three times without a callback ({watcher.renewals}, {seen}, {watcher.error})")
        session.lock()
        deadline = time.monotonic() + 1
        while not seen and time.monotonic() < deadline:
            time.sleep(0.02)
        checks.check(seen == [3], f"watcher reports lock status 3 within 1s ({seen})")
        time.sleep(0.3)
        checks.check(seen == [3], "watcher does not repeat the lock callback")
    finally:
        watcher.close()
    return None


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "--role":
        return run_role(argv[2:])
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--only", default="")
    options = parser.parse_args(argv[1:])
    build = Path(options.build_dir).resolve()
    library = build / "libkilix-secrets.so.0"
    delegated = _delegate_sanitizer_preload(library, argv)
    if delegated is not None:
        return delegated
    os.environ["KILIX_SECRETS_LIBRARY"] = str(library)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    sys.path.insert(0, str(PACKAGE_PARENT))
    scratch = Path(os.environ.get("TMPDIR", ""))
    checks = Checks()
    checks.check(scratch.is_absolute() and scratch.is_dir() and not scratch.is_symlink(),
                 "TMPDIR is an absolute existing non-symlink directory")
    root = Path(tempfile.mkdtemp(prefix="ksec-python.", dir=scratch))
    runtime = root / "runtime"
    socket_path = runtime / "kilix-secrets" / "control.sock"
    data_dir = root / "data"
    runtime.mkdir(mode=0o700)
    process = None
    selected = set(options.only.split(",")) if options.only else set()

    def wanted(name: str) -> bool:
        return not selected or name in selected

    try:
        if wanted("library"):
            test_library(checks, library)
        if wanted("seal"):
            test_seal_files(checks, root)
        if wanted("worker") or wanted("vault"):
            daemon = build / "kilix-secretsd"
            process = start_daemon(daemon, socket_path, data_dir)
            checks.check(process.poll() is None, "private daemon is running")
            checks.check(stat.S_IMODE(socket_path.parent.stat().st_mode) == 0o700,
                         "socket directory mode is 0700")
            checks.check(stat.S_IMODE(socket_path.stat().st_mode) == 0o600,
                         "socket mode is 0600")
        if wanted("worker"):
            test_worker(checks, socket_path)
            test_connect_env(checks, socket_path, runtime)
        if wanted("vault"):
            test_vault(checks, socket_path)
    finally:
        stop_daemon(process)
        resolved = root.resolve()
        if resolved.parent == scratch.resolve() and resolved.name.startswith("ksec-python."):
            import shutil
            shutil.rmtree(resolved)
    print(f"python binding checks: {checks.total - checks.failed}/{checks.total} passed")
    return 0 if checks.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
