"""Capability-holding worker. Spawned as ``python -m kilix_secrets.worker``.

The parent is the supervisor: it mints the capability and passes the
descriptor with SCM_RIGHTS. Frames are length-prefixed JSON. Unknown methods
are refused. The process exits when its parent dies or the control socket
closes.
"""

from __future__ import annotations

import ctypes
import os
import signal
import socket
import sys

from kilix_secrets._binding import (
    RECORD_ID_BYTES,
    Client,
    Field,
    Grant,
    IdentityInfo,
    Invalid,
    KilixSecretsError,
    ProtocolError,
    Record,
    zero,
)
from kilix_secrets._files import seal_file, unseal_file
from kilix_secrets._protocol import (
    FrameError,
    b64decode,
    b64encode,
    close_fds,
    recv_frame,
    send_frame,
)

_PR_SET_PDEATHSIG = 1


def _arm_parent_death() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [
        ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
    ]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(_PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
        os._exit(1)
    if os.getppid() == 1:
        os._exit(0)


def _on_term(_signum: int, _frame: object) -> None:
    os._exit(0)


class _State:
    def __init__(self) -> None:
        self.client: Client | None = None


def _need_client(state: _State) -> Client:
    if state.client is None:
        raise Invalid("worker is not connected")
    return state.client


def _record(msg: dict) -> Record:
    fields = []
    for item in msg.get("fields") or []:
        value = b64decode(item["value"])
        try:
            fields.append(Field(item["name"], bytes(value)))
        finally:
            zero(value)
    grants = [
        Grant(item["application_id"], int(item["verbs"]))
        for item in (msg.get("grants") or [])
    ]
    return Record(
        owner=msg["owner"],
        type=msg["type"],
        label=msg["label"],
        expires_at=int(msg.get("expires_at") or 0),
        fields=fields,
        grants=grants,
    )


def _info(info: IdentityInfo) -> dict:
    return {
        "version": info.version,
        "vault_uuid": b64encode(info.vault_uuid),
        "record_id": b64encode(info.record_id),
        "record_revision": info.record_revision,
        "public_key": b64encode(info.public_key),
        "anchor": b64encode(info.anchor),
    }


def _hello(state: _State, msg: dict, fds: list[int]) -> dict:
    if state.client is not None:
        raise Invalid("worker is already connected")
    if len(fds) != 1:
        raise Invalid("hello requires a capability descriptor")
    cap = fds[0]
    fds[0] = -1
    state.client = Client.connect_at(msg["socket"], cap)
    return {}


def _vault_init(state: _State, msg: dict, fds: list[int]) -> dict:
    del msg
    if len(fds) != 1:
        raise Invalid("vault_init requires a passphrase descriptor")
    secret = _read_fd_secret(fds[0])
    try:
        recovery = _need_client(state).vault_init(secret)
    finally:
        zero(secret)
    try:
        return {"recovery": b64encode(recovery)}
    finally:
        zero(recovery)


def _read_fd_secret(fd: int) -> bytearray:
    from kilix_secrets._binding import read_secret_fd
    return read_secret_fd(fd, 1024)


def _unlock(state: _State, msg: dict, fds: list[int]) -> dict:
    if len(fds) != 1:
        raise Invalid("unlock requires a secret descriptor")
    secret = _read_fd_secret(fds[0])
    try:
        _need_client(state).unlock(int(msg["slot"]), secret)
    finally:
        zero(secret)
    return {}


def _lock(state: _State, msg: dict, fds: list[int]) -> dict:
    del msg, fds
    _need_client(state).lock()
    return {}


def _change_passphrase(state: _State, msg: dict, fds: list[int]) -> dict:
    del msg
    if len(fds) != 1:
        raise Invalid("change_passphrase requires a passphrase descriptor")
    secret = _read_fd_secret(fds[0])
    try:
        _need_client(state).change_passphrase(secret)
    finally:
        zero(secret)
    return {}


def _rotate(state: _State, msg: dict, fds: list[int]) -> dict:
    del msg
    if len(fds) != 2:
        raise Invalid("rotate_master requires passphrase and recovery descriptors")
    passphrase = _read_fd_secret(fds[0])
    recovery = _read_fd_secret(fds[1])
    try:
        _need_client(state).rotate_master(passphrase, recovery)
    finally:
        zero(passphrase)
        zero(recovery)
    return {}


def _export(state: _State, msg: dict, fds: list[int]) -> dict:
    del msg
    if len(fds) != 2:
        raise Invalid("export_backup requires passphrase and output descriptors")
    secret = _read_fd_secret(fds[0])
    try:
        _need_client(state).export_backup(secret, fds[1])
    finally:
        zero(secret)
    return {}


def _import(state: _State, msg: dict, fds: list[int]) -> dict:
    del msg
    if len(fds) != 2:
        raise Invalid("import_backup requires passphrase and input descriptors")
    secret = _read_fd_secret(fds[0])
    try:
        _need_client(state).import_backup(secret, fds[1])
    finally:
        zero(secret)
    return {}


def _reset(state: _State, msg: dict, fds: list[int]) -> dict:
    if len(fds) != 1:
        raise Invalid("reset_vault requires a passphrase descriptor")
    secret = _read_fd_secret(fds[0])
    try:
        recovery = _need_client(state).reset_vault(msg["confirmation"], secret)
    finally:
        zero(secret)
    try:
        return {"recovery": b64encode(recovery)}
    finally:
        zero(recovery)


def _put(state: _State, msg: dict, fds: list[int]) -> dict:
    del fds
    record_id = _need_client(state).put(_record(msg))
    return {"record_id": b64encode(record_id)}


def _replace(state: _State, msg: dict, fds: list[int]) -> dict:
    del fds
    record_id = bytes(b64decode(msg["record_id"]))
    if len(record_id) != RECORD_ID_BYTES:
        raise Invalid("record id must be 16 bytes")
    _need_client(state).replace(record_id, _record(msg))
    return {}


def _get(state: _State, msg: dict, fds: list[int]) -> dict:
    del fds
    record_id = bytes(b64decode(msg["record_id"]))
    max_len = msg.get("max_len")
    buf = _need_client(state).get(
        record_id, msg["field"], None if max_len is None else int(max_len))
    try:
        return {"secret": b64encode(buf)}
    finally:
        zero(buf)


def _identity_open(state: _State, msg: dict, fds: list[int]) -> tuple[dict, list[int]]:
    del fds
    record_id = bytes(b64decode(msg["record_id"]))
    anchor = bytes(b64decode(msg["anchor"])) if msg.get("anchor") else None
    opened = _need_client(state).identity_open(record_id, anchor)
    try:
        body = {"private_key": b64encode(opened.private_key), "info": _info(opened.info)}
        lease = opened.lease_fd
        opened.lease_fd = -1
        return body, [lease]
    finally:
        zero(opened.private_key)


def _identity_info(state: _State, msg: dict, fds: list[int]) -> dict:
    del fds
    record_id = bytes(b64decode(msg["record_id"]))
    anchor = bytes(b64decode(msg["anchor"])) if msg.get("anchor") else None
    return {"info": _info(_need_client(state).identity_info(record_id, anchor))}


def _delete(state: _State, msg: dict, fds: list[int]) -> dict:
    del fds
    _need_client(state).delete(bytes(b64decode(msg["record_id"])))
    return {}


def _list(state: _State, msg: dict, fds: list[int]) -> dict:
    del msg, fds
    return {"body": b64encode(_need_client(state).list())}


def _show(state: _State, msg: dict, fds: list[int]) -> dict:
    del fds
    return {"body": b64encode(_need_client(state).show(bytes(b64decode(msg["record_id"]))))}


def _grant(state: _State, msg: dict, fds: list[int]) -> dict:
    del fds
    _need_client(state).grant(
        bytes(b64decode(msg["record_id"])), msg["application_id"], int(msg["verbs"]))
    return {}


def _revoke(state: _State, msg: dict, fds: list[int]) -> dict:
    del fds
    _need_client(state).revoke(bytes(b64decode(msg["record_id"])), msg["application_id"])
    return {}


def _doctor(state: _State, msg: dict, fds: list[int]) -> dict:
    del msg, fds
    return {"body": b64encode(_need_client(state).doctor())}


def _compact(state: _State, msg: dict, fds: list[int]) -> dict:
    del msg, fds
    _need_client(state).compact()
    return {}


def _dataset_create(state: _State, msg: dict, fds: list[int]) -> dict:
    del fds
    return {"record_id": b64encode(_need_client(state).dataset_create(msg["label"]))}


def _seal_fd(state: _State, msg: dict, fds: list[int]) -> dict:
    if len(fds) != 2:
        raise Invalid("seal_fd requires input and output descriptors")
    _need_client(state).seal_fd(
        bytes(b64decode(msg["record_id"])), msg["name"], int(msg["revision"]),
        fds[0], fds[1])
    return {}


def _unseal_fd(state: _State, msg: dict, fds: list[int]) -> dict:
    if len(fds) != 2:
        raise Invalid("unseal_fd requires input and output descriptors")
    revision = _need_client(state).unseal_fd(
        bytes(b64decode(msg["record_id"])), msg["name"], fds[0], fds[1])
    return {"revision": revision}


def _seal_file(state: _State, msg: dict, fds: list[int]) -> dict:
    del fds
    seal_file(
        _need_client(state), bytes(b64decode(msg["record_id"])), msg["name"],
        int(msg["revision"]), msg["source"], msg["target"])
    return {}


def _unseal_file(state: _State, msg: dict, fds: list[int]) -> dict:
    del fds
    revision = unseal_file(
        _need_client(state), bytes(b64decode(msg["record_id"])), msg["name"],
        msg["source"], msg["target"])
    return {"revision": revision}


def _status(state: _State, msg: dict, fds: list[int]) -> dict:
    del msg, fds
    return {"flags": _need_client(state).status()}


def _watch(state: _State, msg: dict, fds: list[int]) -> tuple[dict, list[int]]:
    del msg, fds
    return {}, [_need_client(state).watch()]


def _result_string(state: _State, msg: dict, fds: list[int]) -> dict:
    del state, fds
    from kilix_secrets._binding import result_string
    return {"text": result_string(int(msg["code"]))}


HANDLERS = {
    "hello": _hello,
    "vault_init": _vault_init,
    "unlock": _unlock,
    "lock": _lock,
    "change_passphrase": _change_passphrase,
    "rotate_master": _rotate,
    "export_backup": _export,
    "import_backup": _import,
    "reset_vault": _reset,
    "put": _put,
    "replace": _replace,
    "get": _get,
    "identity_open": _identity_open,
    "identity_info": _identity_info,
    "delete": _delete,
    "list": _list,
    "show": _show,
    "grant": _grant,
    "revoke": _revoke,
    "doctor": _doctor,
    "compact": _compact,
    "dataset_create": _dataset_create,
    "seal_fd": _seal_fd,
    "unseal_fd": _unseal_fd,
    "seal_file": _seal_file,
    "unseal_file": _unseal_file,
    "status": _status,
    "watch": _watch,
    "result_string": _result_string,
}


def _error(message_id: object, exc: KilixSecretsError) -> dict:
    return {
        "id": message_id,
        "ok": False,
        "code": int(exc.code),
        "error": type(exc).__name__,
        "message": str(exc),
    }


def serve(sock: socket.socket) -> None:
    state = _State()
    try:
        while True:
            if os.getppid() == 1:
                return
            try:
                message, fds = recv_frame(sock)
            except EOFError:
                return
            except FrameError:
                return
            message_id = message.get("id")
            method = message.get("method")
            reply_fds: list[int] = []
            try:
                if not isinstance(method, str) or method not in HANDLERS:
                    send_frame(sock, _error(message_id, Invalid("unknown method")))
                    continue
                try:
                    outcome = HANDLERS[method](state, message, fds)
                except KilixSecretsError as exc:
                    send_frame(sock, _error(message_id, exc))
                    continue
                except (KeyError, TypeError, ValueError):
                    send_frame(sock, _error(message_id, Invalid("invalid request")))
                    continue
                except Exception as exc:
                    send_frame(sock, _error(
                        message_id, ProtocolError(f"worker handler failed: {type(exc).__name__}")))
                    continue
                body: dict
                if isinstance(outcome, tuple):
                    body, reply_fds = outcome
                else:
                    body = outcome
                reply = {"id": message_id, "ok": True}
                reply.update(body)
                send_frame(sock, reply, reply_fds)
            finally:
                close_fds(fds)
                close_fds(reply_fds)
    finally:
        if state.client is not None:
            state.client.close()


def main() -> int:
    _arm_parent_death()
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    raw = os.environ.get("KILIX_SECRETS_WORKER_FD")
    if raw is None or not raw.isdigit():
        return 2
    fd = int(raw)
    os.environ.pop("KILIX_SECRETS_WORKER_FD", None)
    sock = socket.socket(fileno=fd)
    try:
        sock.setblocking(True)
        serve(sock)
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
