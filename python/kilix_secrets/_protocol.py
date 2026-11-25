"""Length-prefixed JSON frames with SCM_RIGHTS descriptors. No pickle."""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
from typing import Any

MAX_FRAME = 1024 * 1024
_HEADER = struct.Struct(">I")


class FrameError(Exception):
    """A frame could not be parsed. The worker treats this as fatal."""


def b64encode(data: bytes | bytearray) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(text: str) -> bytearray:
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise FrameError("invalid base64") from exc
    return bytearray(raw)


def tune(sock: socket.socket) -> None:
    for option in (socket.SO_SNDBUF, socket.SO_RCVBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, option, 2 * 1024 * 1024)
        except OSError:
            pass


def send_frame(sock: socket.socket, payload: dict[str, Any],
               fds: list[int] | None = None) -> None:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(body) > MAX_FRAME:
        raise FrameError("frame exceeds 1 MiB")
    message = _HEADER.pack(len(body)) + body
    ancillary: list[tuple[int, int, bytes]] = []
    if fds:
        ancillary.append((
            socket.SOL_SOCKET,
            socket.SCM_RIGHTS,
            struct.pack("@" + "i" * len(fds), *fds),
        ))
    sock.sendmsg([message], ancillary)


def recv_frame(sock: socket.socket) -> tuple[dict[str, Any], list[int]]:
    flags = getattr(socket, "MSG_CMSG_CLOEXEC", 0)
    try:
        message, ancdata, msg_flags, _addr = sock.recvmsg(
            MAX_FRAME + _HEADER.size, socket.CMSG_SPACE(256), flags)
    except InterruptedError:
        return recv_frame(sock)
    if not message:
        raise EOFError
    if msg_flags & getattr(socket, "MSG_TRUNC", 0):
        raise FrameError("frame truncated")
    if msg_flags & getattr(socket, "MSG_CTRUNC", 0):
        raise FrameError("descriptor message truncated")
    fds: list[int] = []
    for level, kind, data in ancdata:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            count = len(data) // struct.calcsize("@i")
            fds.extend(struct.unpack("@" + "i" * count, data[:count * struct.calcsize("@i")]))
    if len(message) < _HEADER.size:
        _close_fds(fds)
        raise FrameError("short frame")
    (length,) = _HEADER.unpack_from(message)
    body = message[_HEADER.size:]
    if length != len(body) or length > MAX_FRAME:
        _close_fds(fds)
        raise FrameError("frame length mismatch")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        _close_fds(fds)
        raise FrameError("frame is not json") from exc
    if not isinstance(payload, dict):
        _close_fds(fds)
        raise FrameError("frame is not an object")
    return payload, fds


def close_fds(fds: list[int]) -> None:
    _close_fds(fds)


def _close_fds(fds: list[int]) -> None:
    for fd in fds:
        if isinstance(fd, int) and fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
