"""Atomic seal and unseal publication.

The output is an unnamed file in the target's directory (mode 0600). It is
given a name only after the write and fsync succeed, then renamed over the
target. A crash before that link leaves no directory entry. On any failure
the target is unchanged and a staged name, if one was created, is removed.
"""

from __future__ import annotations

import ctypes
import os
import secrets

from kilix_secrets._binding import Invalid, IoError, KilixSecretsError

_AT_EMPTY_PATH = 0x1000
_libc: ctypes.CDLL | None = None


def _linkat() -> ctypes.CDLL:
    global _libc
    if _libc is None:
        lib = ctypes.CDLL(None, use_errno=True)
        lib.linkat.argtypes = [
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
        ]
        lib.linkat.restype = ctypes.c_int
        _libc = lib
    return _libc


def _link_fd(tmp_fd: int, dir_fd: int, name: str) -> None:
    encoded = os.fsencode(name)
    ctypes.set_errno(0)
    if _linkat().linkat(tmp_fd, b"", dir_fd, encoded, _AT_EMPTY_PATH) == 0:
        return
    err = ctypes.get_errno()
    if err == 17:  # EEXIST
        raise FileExistsError(name)
    raise IoError(os.strerror(err) if err else "linkat failed")


def _unlink(dir_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except OSError:
        pass


def publish(target: str, write_fn) -> None:
    """Write ``write_fn(fd)`` into a 0600 file and rename it onto ``target``."""
    directory, name = os.path.split(os.path.abspath(target))
    if not directory or not name or name in {".", ".."}:
        raise Invalid("target path is invalid")
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    tmp_fd = -1
    staged: str | None = None
    try:
        tmp_fd = os.open(directory, os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600)
        os.fchmod(tmp_fd, 0o600)
        try:
            write_fn(tmp_fd)
            os.fsync(tmp_fd)
        except KilixSecretsError:
            raise
        except OSError as exc:
            raise IoError(os.strerror(exc.errno) if exc.errno else "write failed") from exc
        try:
            _link_fd(tmp_fd, dir_fd, name)
        except FileExistsError:
            staged_name = f".kilix-seal-{os.getpid()}-{secrets.token_hex(8)}"
            _link_fd(tmp_fd, dir_fd, staged_name)
            staged = staged_name
            try:
                os.rename(staged_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            except OSError as exc:
                raise IoError(os.strerror(exc.errno) if exc.errno else "rename failed") from exc
            staged = None
        try:
            os.fsync(dir_fd)
        except OSError as exc:
            raise IoError(os.strerror(exc.errno) if exc.errno else "directory sync failed") from exc
    except BaseException:
        if staged is not None:
            _unlink(dir_fd, staged)
        raise
    finally:
        if tmp_fd >= 0:
            os.close(tmp_fd)
        os.close(dir_fd)


def seal_file(client, record_id: bytes, dataset_name: str, revision: int,
              source: str, target: str) -> None:
    """Seal ``source`` and publish it as ``target``. ``source`` is not modified."""

    def write(out_fd: int) -> None:
        in_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
        try:
            client.seal_fd(record_id, dataset_name, revision, in_fd, out_fd)
        finally:
            os.close(in_fd)

    publish(target, write)


def unseal_file(client, record_id: bytes, dataset_name: str,
                source: str, target: str) -> int:
    """Unseal ``source`` and publish the plaintext as ``target``. Returns the revision."""
    found = {"revision": 0}

    def write(out_fd: int) -> None:
        in_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
        try:
            found["revision"] = client.unseal_fd(record_id, dataset_name, in_fd, out_fd)
        finally:
            os.close(in_fd)

    publish(target, write)
    return int(found["revision"])
