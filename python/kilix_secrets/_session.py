"""Session and Watcher.

A Session mints a capability for a short-lived worker and replaces that
worker when the capability expires, retrying the call once. A Watcher keeps
a WATCH open and renews it before the capability lifetime ends. Renewals do
not call the lock callback.
"""

from __future__ import annotations

import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import threading
import time
from typing import Callable

from kilix_secrets._binding import (
    DENIED,
    EXPIRED,
    LOCKED,
    RECORD_ID_BYTES,
    Field,
    Grant,
    IdentityInfo,
    IdentityOpen,
    Invalid,
    IoError,
    KilixSecretsError,
    ProtocolError,
    Record,
    Status,
    Verb,
    mint_for_child,
    secret_memfd,
    zero,
)
from kilix_secrets._protocol import (
    FrameError,
    b64decode,
    b64encode,
    close_fds,
    recv_frame,
    send_frame,
    tune,
)

_WORKER_ARGV = [sys.executable, "-m", "kilix_secrets.worker"]


class _WorkerDown(IoError):
    pass


def _package_parent() -> str:
    return str(Path(__file__).resolve().parents[1])


def _hold_seconds(lifetime: int) -> float:
    """How long to use a capability before replacing it.

    The daemon's clock is whole seconds, so a lifetime of N can end just
    after N-1 seconds. Renew earlier than that.
    """
    margin = 1.25 if lifetime >= 2 else 0.35
    return max(0.4, float(lifetime) - margin)


class Worker:
    """One ``python -m kilix_secrets.worker`` process and its control socket."""

    def __init__(self) -> None:
        self.proc: subprocess.Popen[bytes] | None = None
        self.sock: socket.socket | None = None
        self.minted_at = 0.0
        self._next_id = 1

    @property
    def pid(self) -> int | None:
        return None if self.proc is None else self.proc.pid

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None and self.sock is not None

    @property
    def age(self) -> float:
        if self.minted_at == 0.0:
            return 0.0
        return time.monotonic() - self.minted_at

    def start(self, socket_path: str, app_id: str, verbs: int, lifetime: int,
              record_id: bytes | None) -> None:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        tune(parent)
        tune(child)
        child_fd = child.detach()
        env = os.environ.copy()
        env.pop("KILIX_SECRETS_CAP_FD", None)
        env["KILIX_SECRETS_WORKER_FD"] = str(child_fd)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        parent_dir = _package_parent()
        previous = env.get("PYTHONPATH")
        env["PYTHONPATH"] = parent_dir if not previous else parent_dir + os.pathsep + previous
        try:
            self.proc = subprocess.Popen(
                _WORKER_ARGV,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=(child_fd,),
                env=env,
            )
        except Exception:
            os.close(child_fd)
            parent.close()
            raise
        os.close(child_fd)
        self.sock = parent
        self.sock.settimeout(180)
        cap = mint_for_child(socket_path, self.proc.pid, app_id, verbs, lifetime, record_id)
        self.minted_at = time.monotonic()
        try:
            self._send({"id": 0, "method": "hello", "socket": socket_path}, [cap])
        finally:
            os.close(cap)
        reply, fds = self._recv()
        close_fds(fds)
        if not reply.get("ok"):
            message = str(reply.get("message") or "worker hello failed")
            self.close()
            code = int(reply.get("code") or 9)
            exc_type = _code_error(code)
            raise exc_type(message, code)

    def request(self, method: str, fields: dict, fds: list[int]) -> tuple[dict, list[int]]:
        if not self.alive or self.sock is None:
            raise _WorkerDown("worker is not running")
        message_id = self._next_id
        self._next_id += 1
        payload = {"id": message_id, "method": method}
        payload.update(fields)
        try:
            self._send(payload, fds)
            reply, out = self._recv()
        except (EOFError, FrameError, OSError, _WorkerDown) as exc:
            detail = self._failure_detail()
            raise _WorkerDown(f"worker call failed{detail}") from exc
        if reply.get("id") != message_id:
            close_fds(out)
            raise ProtocolError("worker reply id mismatch")
        return reply, out

    def _failure_detail(self) -> str:
        proc = self.proc
        if proc is None:
            return ""
        code = proc.poll()
        err = b""
        if proc.stderr is not None:
            try:
                err = proc.stderr.read(2000)
            except Exception:
                err = b""
        text = err.decode("utf-8", "replace").strip()
        return f" (exit {code}): {text}" if text else f" (exit {code})"

    def close(self) -> None:
        sock = self.sock
        proc = self.proc
        self.sock = None
        self.proc = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except OSError:
                    pass
                proc.wait(timeout=2)
        if proc is not None and proc.stderr is not None:
            proc.stderr.close()

    def _send(self, payload: dict, fds: list[int]) -> None:
        if self.sock is None:
            raise _WorkerDown("worker socket is closed")
        send_frame(self.sock, payload, fds)

    def _recv(self) -> tuple[dict, list[int]]:
        if self.sock is None:
            raise _WorkerDown("worker socket is closed")
        return recv_frame(self.sock)


def _code_error(code: int) -> type[KilixSecretsError]:
    from kilix_secrets._binding import _BY_CODE
    return _BY_CODE.get(code, ProtocolError)


def _bytes_field(value: bytes | bytearray, label: str) -> str:
    if not isinstance(value, (bytes, bytearray)):
        raise Invalid(f"{label} must be bytes")
    return b64encode(value)


class Session:
    """Thread-safe proxy in front of a replaceable worker."""

    def __init__(self, socket_path: str, app_id: str, verbs: int,
                 lifetime: int = 300, record_id: bytes | None = None) -> None:
        if not isinstance(lifetime, int) or isinstance(lifetime, bool):
            raise Invalid("lifetime must be a whole number of seconds")
        if lifetime < 1 or lifetime > 300:
            raise Invalid("lifetime must be from 1 to 300 seconds")
        if record_id is not None and (
                not isinstance(record_id, (bytes, bytearray)) or len(record_id) != RECORD_ID_BYTES):
            raise Invalid("record id must be 16 bytes")
        self._socket_path = socket_path
        self._app_id = app_id
        self._verbs = int(verbs)
        self._lifetime = lifetime
        self._record_id = None if record_id is None else bytes(record_id)
        self._lock = threading.RLock()
        self._worker: Worker | None = None
        self._ensure_worker()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def worker_pid(self) -> int | None:
        worker = self._worker
        return None if worker is None else worker.pid

    def close(self) -> None:
        with self._lock:
            worker = self._worker
            self._worker = None
            if worker is not None:
                worker.close()

    def _replace_expired_worker(self) -> None:
        """Replace the worker because its capability expired or is about to."""
        self._start_worker()

    def _should_rotate(self) -> bool:
        worker = self._worker
        if worker is None:
            return False
        return worker.age >= _hold_seconds(self._lifetime)

    def _window_closed(self) -> bool:
        return self._should_rotate()

    def _ensure_worker(self) -> None:
        if self._worker is None or not self._worker.alive:
            self._start_worker()
        elif self._should_rotate():
            self._replace_expired_worker()

    def _start_worker(self) -> None:
        previous = self._worker
        self._worker = None
        if previous is not None:
            previous.close()
        worker = Worker()
        try:
            worker.start(
                self._socket_path, self._app_id, self._verbs, self._lifetime, self._record_id)
        except Exception:
            worker.close()
            raise
        self._worker = worker

    def _exchange(self, method: str, fields: dict, fds: list[int]) -> tuple[dict, list[int]]:
        worker = self._worker
        if worker is None:
            raise IoError("session has no worker")
        return worker.request(method, fields, fds)

    def _call(self, method: str, fields: dict | None = None,
              fd_factory: Callable[[], list[int]] | None = None,
              restart: bool = False) -> tuple[dict, list[int]]:
        fields = fields or {}
        with self._lock:
            self._ensure_worker()
            reply, out = self._attempt(method, fields, fd_factory)
            code = int(reply.get("code") or 0)
            if not reply.get("ok") and self._should_retry(code):
                close_fds(out)
                self._replace_expired_worker()
                reply, out = self._attempt(method, fields, fd_factory)
            if not reply.get("ok"):
                close_fds(out)
                exc_type = _code_error(int(reply.get("code") or 9))
                raise exc_type(str(reply.get("message") or "worker call failed"),
                               int(reply.get("code") or 9))
            if restart:
                # These operations clear the calling capability.
                self._start_worker()
            return reply, out

    def _attempt(self, method: str, fields: dict,
                 fd_factory: Callable[[], list[int]] | None) -> tuple[dict, list[int]]:
        fds = fd_factory() if fd_factory is not None else []
        try:
            return self._exchange(method, fields, fds)
        finally:
            close_fds(fds)

    def _should_retry(self, code: int) -> bool:
        if code == int(EXPIRED):
            return True
        if code == int(DENIED) and self._window_closed():
            return True
        return False

    def _secret_fds(self, *secrets: bytes | bytearray) -> Callable[[], list[int]]:
        def factory() -> list[int]:
            return [secret_memfd(item) for item in secrets]
        return factory

    def _body(self, method: str, fields: dict | None = None,
              fd_factory: Callable[[], list[int]] | None = None) -> bytes:
        reply, fds = self._call(method, fields, fd_factory)
        close_fds(fds)
        raw = b64decode(reply["body"])
        try:
            return bytes(raw)
        finally:
            zero(raw)

    def _secret_body(self, key: str, method: str, fields: dict | None = None,
                     fd_factory: Callable[[], list[int]] | None = None,
                     restart: bool = False) -> bytearray:
        reply, fds = self._call(method, fields, fd_factory, restart=restart)
        close_fds(fds)
        return b64decode(reply[key])

    def vault_init(self, passphrase: bytes | bytearray) -> bytearray:
        return self._secret_body("recovery", "vault_init", {}, self._secret_fds(passphrase))

    def unlock(self, slot: int, secret: bytes | bytearray) -> None:
        self._call("unlock", {"slot": int(slot)}, self._secret_fds(secret))

    def lock(self) -> None:
        self._call("lock", restart=True)

    def change_passphrase(self, passphrase: bytes | bytearray) -> None:
        self._call("change_passphrase", {}, self._secret_fds(passphrase))

    def rotate_master(self, passphrase: bytes | bytearray, recovery: bytes | bytearray) -> None:
        self._call("rotate_master", {}, self._secret_fds(passphrase, recovery), restart=True)

    def export_backup(self, passphrase: bytes | bytearray, output_path: str) -> None:
        def factory() -> list[int]:
            out = os.open(output_path, os.O_RDWR | os.O_CLOEXEC)
            try:
                return [secret_memfd(passphrase), out]
            except Exception:
                os.close(out)
                raise
        self._call("export_backup", {}, factory)

    def import_backup(self, passphrase: bytes | bytearray, input_path: str) -> None:
        def factory() -> list[int]:
            inp = os.open(input_path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                return [secret_memfd(passphrase), inp]
            except Exception:
                os.close(inp)
                raise
        self._call("import_backup", {}, factory, restart=True)

    def reset_vault(self, confirmation: str, passphrase: bytes | bytearray) -> bytearray:
        return self._secret_body(
            "recovery", "reset_vault", {"confirmation": confirmation},
            self._secret_fds(passphrase), restart=True)

    def _record_fields(self, record: Record) -> dict:
        if record.fields is None or record.grants is None:
            raise Invalid("record fields are missing")
        return {
            "owner": record.owner,
            "type": record.type,
            "label": record.label,
            "expires_at": int(record.expires_at),
            "fields": [
                {"name": field.name, "value": _bytes_field(field.value, "field")}
                for field in record.fields
            ],
            "grants": [
                {"application_id": grant.application_id, "verbs": int(grant.verbs)}
                for grant in record.grants
            ],
        }

    def put(self, record: Record) -> bytes:
        reply, fds = self._call("put", self._record_fields(record))
        close_fds(fds)
        raw = b64decode(reply["record_id"])
        try:
            if len(raw) != RECORD_ID_BYTES:
                raise ProtocolError("record id length is not 16")
            return bytes(raw)
        finally:
            zero(raw)

    def replace(self, record_id: bytes, record: Record) -> None:
        fields = self._record_fields(record)
        fields["record_id"] = _bytes_field(record_id, "record id")
        self._call("replace", fields)

    def get(self, record_id: bytes, field: str, max_len: int | None = None) -> bytearray:
        fields: dict = {
            "record_id": _bytes_field(record_id, "record id"),
            "field": field,
        }
        if max_len is not None:
            fields["max_len"] = int(max_len)
        return self._secret_body("secret", "get", fields)

    def identity_open(self, record_id: bytes, expected_anchor: bytes | None = None) -> IdentityOpen:
        fields: dict = {"record_id": _bytes_field(record_id, "record id")}
        if expected_anchor is not None:
            fields["anchor"] = _bytes_field(expected_anchor, "anchor")
        reply, fds = self._call("identity_open", fields)
        private = b64decode(reply["private_key"])
        if len(fds) != 1:
            zero(private)
            close_fds(fds)
            raise ProtocolError("identity open returned no lease")
        info = _parse_info(reply["info"])
        return IdentityOpen(private, info, fds[0])

    def identity_info(self, record_id: bytes, expected_anchor: bytes | None = None) -> IdentityInfo:
        fields: dict = {"record_id": _bytes_field(record_id, "record id")}
        if expected_anchor is not None:
            fields["anchor"] = _bytes_field(expected_anchor, "anchor")
        reply, fds = self._call("identity_info", fields)
        close_fds(fds)
        return _parse_info(reply["info"])

    def delete(self, record_id: bytes) -> None:
        self._call("delete", {"record_id": _bytes_field(record_id, "record id")})

    def list(self) -> bytes:
        return self._body("list")

    def show(self, record_id: bytes) -> bytes:
        return self._body("show", {"record_id": _bytes_field(record_id, "record id")})

    def grant(self, record_id: bytes, application_id: str, verbs: int) -> None:
        self._call("grant", {
            "record_id": _bytes_field(record_id, "record id"),
            "application_id": application_id,
            "verbs": int(verbs),
        })

    def revoke(self, record_id: bytes, application_id: str) -> None:
        self._call("revoke", {
            "record_id": _bytes_field(record_id, "record id"),
            "application_id": application_id,
        })

    def doctor(self) -> bytes:
        return self._body("doctor")

    def compact(self) -> None:
        self._call("compact")

    def dataset_create(self, label: str) -> bytes:
        reply, fds = self._call("dataset_create", {"label": label})
        close_fds(fds)
        raw = b64decode(reply["record_id"])
        try:
            return bytes(raw)
        finally:
            zero(raw)

    def seal_fd(self, record_id: bytes, dataset_name: str, revision: int,
                input_fd: int, output_fd: int) -> None:
        def factory() -> list[int]:
            return [os.dup(input_fd), os.dup(output_fd)]
        self._call("seal_fd", {
            "record_id": _bytes_field(record_id, "record id"),
            "name": dataset_name,
            "revision": int(revision),
        }, factory)

    def unseal_fd(self, record_id: bytes, dataset_name: str,
                  input_fd: int, output_fd: int) -> int:
        def factory() -> list[int]:
            return [os.dup(input_fd), os.dup(output_fd)]
        reply, fds = self._call("unseal_fd", {
            "record_id": _bytes_field(record_id, "record id"),
            "name": dataset_name,
        }, factory)
        close_fds(fds)
        return int(reply["revision"])

    def seal_file(self, record_id: bytes, dataset_name: str, revision: int,
                  source: str, target: str) -> None:
        self._call("seal_file", {
            "record_id": _bytes_field(record_id, "record id"),
            "name": dataset_name,
            "revision": int(revision),
            "source": os.path.abspath(source),
            "target": os.path.abspath(target),
        })

    def unseal_file(self, record_id: bytes, dataset_name: str,
                    source: str, target: str) -> int:
        reply, fds = self._call("unseal_file", {
            "record_id": _bytes_field(record_id, "record id"),
            "name": dataset_name,
            "source": os.path.abspath(source),
            "target": os.path.abspath(target),
        })
        close_fds(fds)
        return int(reply["revision"])

    def status(self) -> int:
        reply, fds = self._call("status")
        close_fds(fds)
        return int(reply["flags"])

    def watch(self) -> int:
        _reply, fds = self._call("watch")
        if len(fds) != 1:
            close_fds(fds)
            raise ProtocolError("watch returned no descriptor")
        return fds[0]

    def result_string(self, code: int) -> str:
        reply, fds = self._call("result_string", {"code": int(code)})
        close_fds(fds)
        return str(reply["text"])


def _parse_info(payload: dict) -> IdentityInfo:
    return IdentityInfo(
        version=int(payload["version"]),
        vault_uuid=bytes(b64decode(payload["vault_uuid"])),
        record_id=bytes(b64decode(payload["record_id"])),
        record_revision=int(payload["record_revision"]),
        public_key=bytes(b64decode(payload["public_key"])),
        anchor=bytes(b64decode(payload["anchor"])),
    )


def _is_lock(flags: int) -> bool:
    return (flags & Status.INITIALIZED) != 0 and (flags & Status.UNLOCKED) == 0


def _poll_hup(fd: int, timeout: float) -> bool:
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
    events = poller.poll(max(0, int(timeout * 1000)))
    if not events:
        return False
    return True


class Watcher:
    """Hold a WATCH and call ``callback(status)`` once per transition to locked.

    The watch is renewed ``lifetime - margin`` seconds after it is minted.
    A renewal does not call ``callback``.
    """

    def __init__(self, socket_path: str, app_id: str, callback: Callable[[int], None],
                 lifetime: int = 30, verbs: int = Verb.READ) -> None:
        if lifetime < 1 or lifetime > 300:
            raise Invalid("lifetime must be from 1 to 300 seconds")
        self._socket_path = socket_path
        self._app_id = app_id
        self._callback = callback
        self._lifetime = int(lifetime)
        self._verbs = int(verbs)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._renewals = 0
        self._notified = False
        self._error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, name="kilix-secrets-watch", daemon=True)
        self._thread.start()

    def __enter__(self) -> "Watcher":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def renewals(self) -> int:
        with self._lock:
            return self._renewals

    @property
    def error(self) -> BaseException | None:
        return self._error

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _count_renewal(self) -> None:
        with self._lock:
            self._renewals += 1

    def _run(self) -> None:
        while not self._stop.is_set():
            worker = Worker()
            watch_fd = -1
            try:
                worker.start(
                    self._socket_path, self._app_id, self._verbs,
                    self._lifetime, None)
                reply, fds = worker.request("watch", {}, [])
                if not reply.get("ok"):
                    close_fds(fds)
                    if int(reply.get("code") or 0) == int(LOCKED):
                        self._consider_status(self._fresh_status())
                    if self._stop.wait(0.2):
                        return
                    continue
                if len(fds) != 1:
                    close_fds(fds)
                    raise ProtocolError("watch returned no descriptor")
                watch_fd = fds[0]
                deadline = time.monotonic() + _hold_seconds(self._lifetime)
                hungup = False
                while not self._stop.is_set():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    if _poll_hup(watch_fd, min(remaining, 0.2)):
                        hungup = True
                        break
                if self._stop.is_set():
                    break
                if hungup:
                    status = self._fresh_status()
                    if status is not None and _is_lock(status):
                        self._deliver_lock(status)
                    else:
                        self._count_renewal()
                        self._notified = False
                else:
                    self._count_renewal()
                    self._after_renewal(self._fresh_status())
            except Exception as exc:
                self._error = exc
                if self._stop.wait(0.2):
                    return
            finally:
                if watch_fd >= 0:
                    os.close(watch_fd)
                worker.close()

    def _after_renewal(self, status: int | None) -> None:
        """Renewal is not a lock notification. A lock observed while renewing is."""
        if status is None:
            return
        if _is_lock(status):
            self._deliver_lock(status)
        elif (status & Status.UNLOCKED) != 0:
            self._notified = False

    def _consider_status(self, status: int | None) -> None:
        if status is not None and _is_lock(status):
            self._deliver_lock(status)
        elif status is not None and (status & Status.UNLOCKED) != 0:
            self._notified = False

    def _deliver_lock(self, status: int) -> None:
        if self._notified:
            return
        self._notified = True
        self._callback(status)

    def _fresh_status(self) -> int | None:
        worker = Worker()
        try:
            worker.start(
                self._socket_path, self._app_id, self._verbs, self._lifetime, None)
            reply, fds = worker.request("status", {}, [])
            close_fds(fds)
            if not reply.get("ok"):
                return None
            return int(reply["flags"])
        except Exception:
            return None
        finally:
            worker.close()
