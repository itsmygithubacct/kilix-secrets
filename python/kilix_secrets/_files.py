"""Atomic seal and unseal publication.

The output is an unnamed file in the target's directory (mode 0600). It is
given a name only after the write and fsync succeed, then renamed over the
target. A crash before that link leaves no directory entry. On any failure
the target is unchanged and a staged name, if one was created, is removed.
"""

from __future__ import annotations

import os
import secrets

from kilix_secrets._binding import (
    Invalid,
    IoError,
    KilixSecretsError,
    require_revision,
    require_text,
)


def _link_fd(tmp_fd: int, dir_fd: int, name: str) -> None:
    """Link an O_TMPFILE inode via /proc/self/fd. No AT_EMPTY_PATH."""
    try:
        os.link(
            f"/proc/self/fd/{tmp_fd}",
            name,
            dst_dir_fd=dir_fd,
            follow_symlinks=True,
        )
    except FileExistsError:
        raise FileExistsError(name) from None
    except OSError as exc:
        raise IoError(os.strerror(exc.errno) if exc.errno else "link failed") from exc


def _unlink(dir_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except OSError:
        pass


def publish(target: str, write_fn) -> None:
    """Write ``write_fn(fd)`` into a 0600 file and rename it onto ``target``."""
    target = require_text(target, "target path")
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
    dataset_name = require_text(dataset_name, "dataset name")
    revision = require_revision(revision)
    source = require_text(source, "source path")
    target = require_text(target, "target path")

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
    dataset_name = require_text(dataset_name, "dataset name")
    source = require_text(source, "source path")
    target = require_text(target, "target path")
    found = {"revision": 0}

    def write(out_fd: int) -> None:
        in_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
        try:
            found["revision"] = client.unseal_fd(record_id, dataset_name, in_fd, out_fd)
        finally:
            os.close(in_fd)

    publish(target, write)
    return int(found["revision"])
