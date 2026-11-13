"""ctypes binding of the public kilix-secrets C API.

Secrets cross into C only through memfds. The caller-facing ``get`` path
returns a ``bytearray`` so the caller can wipe it.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
from dataclasses import dataclass
import threading
from typing import Callable


RECORD_ID_BYTES = 16
CAPABILITY_BYTES = 32
MAX_APP_ID = 64
MAX_FIELD_NAME = 32
MAX_FIELDS = 8
MAX_GRANTS = 16
MAX_SECRET_BYTES = 65536
IDENTITY_KEY_BYTES = 32
IDENTITY_ANCHOR_BYTES = 32
MAX_DATASET_NAME = 128
MAX_DATASET_BYTES = 64 * 1024 * 1024
# Matches ksec_dataset_sealed_length at the maximum plaintext and prefix.
_DATASET_PREFIX_FIXED_BYTES = 68
_DATASET_CHUNK_BYTES = 65536
_DATASET_CHUNK_OVERHEAD = 17
_DATASET_STREAM_HEADER_BYTES = 24
_UINT64_MAX = (1 << 64) - 1
RESET_CONFIRMATION = "RESET-VAULT-AND-LOSE-IDENTITY"
IDENTITY_OWNER = "kilix-pairingd"
IDENTITY_TYPE = "device-identity"
IDENTITY_FIELD = "private-key"
DATASET_KEY_TYPE = "dataset-key"
DATASET_KEY_FIELD = "dataset-key"

_F_ADD_SEALS = getattr(__import__("fcntl"), "F_ADD_SEALS", 1033)
_F_SEAL = (
    getattr(__import__("fcntl"), "F_SEAL_SEAL", 0x0001)
    | getattr(__import__("fcntl"), "F_SEAL_SHRINK", 0x0002)
    | getattr(__import__("fcntl"), "F_SEAL_GROW", 0x0004)
    | getattr(__import__("fcntl"), "F_SEAL_WRITE", 0x0008)
)


class Result(int):
    """Integer result code. Compare with ``==``; it is not an ``IntEnum``
    so existing integer codes keep working without wrapping."""

    def __new__(cls, value: int, name: str) -> "Result":
        obj = int.__new__(cls, value)
        obj.name = name
        return obj

    def __repr__(self) -> str:
        return f"Result.{self.name}"


def _results() -> dict[str, Result]:
    names = [
        ("OK", 0),
        ("LOCKED", 1),
        ("DENIED", 2),
        ("NOT_FOUND", 3),
        ("EXPIRED", 4),
        ("INVALID", 5),
        ("LIMIT", 6),
        ("IO", 7),
        ("CRYPTO", 8),
        ("PROTOCOL", 9),
        ("BUSY", 10),
        ("EXISTS", 11),
        ("AUDIT", 12),
        ("MEMORY", 13),
        ("CONFLICT", 14),
    ]
    return {name: Result(value, name) for name, value in names}


_RESULT = _results()
OK = _RESULT["OK"]
LOCKED = _RESULT["LOCKED"]
DENIED = _RESULT["DENIED"]
NOT_FOUND = _RESULT["NOT_FOUND"]
EXPIRED = _RESULT["EXPIRED"]
INVALID = _RESULT["INVALID"]
LIMIT = _RESULT["LIMIT"]
IO = _RESULT["IO"]
CRYPTO = _RESULT["CRYPTO"]
PROTOCOL = _RESULT["PROTOCOL"]
BUSY = _RESULT["BUSY"]
EXISTS = _RESULT["EXISTS"]
AUDIT = _RESULT["AUDIT"]
MEMORY = _RESULT["MEMORY"]
CONFLICT = _RESULT["CONFLICT"]


class ResultCode:
    OK = OK
    LOCKED = LOCKED
    DENIED = DENIED
    NOT_FOUND = NOT_FOUND
    EXPIRED = EXPIRED
    INVALID = INVALID
    LIMIT = LIMIT
    IO = IO
    CRYPTO = CRYPTO
    PROTOCOL = PROTOCOL
    BUSY = BUSY
    EXISTS = EXISTS
    AUDIT = AUDIT
    MEMORY = MEMORY
    CONFLICT = CONFLICT


# Public name used by callers. A class of ints keeps ``Result.LOCKED == 1``.
class _ResultNS:
    OK = OK
    LOCKED = LOCKED
    DENIED = DENIED
    NOT_FOUND = NOT_FOUND
    EXPIRED = EXPIRED
    INVALID = INVALID
    LIMIT = LIMIT
    IO = IO
    CRYPTO = CRYPTO
    PROTOCOL = PROTOCOL
    BUSY = BUSY
    EXISTS = EXISTS
    AUDIT = AUDIT
    MEMORY = MEMORY
    CONFLICT = CONFLICT

    def __iter__(self):
        return iter(
            (
                OK, LOCKED, DENIED, NOT_FOUND, EXPIRED, INVALID, LIMIT, IO,
                CRYPTO, PROTOCOL, BUSY, EXISTS, AUDIT, MEMORY, CONFLICT,
            )
        )


Result = _ResultNS  # type: ignore[misc,assignment]


class Verb:
    CREATE = 1 << 0
    READ = 1 << 1
    REPLACE = 1 << 2
    DELETE = 1 << 3
    LIST_OWN = 1 << 4
    USE = 1 << 5
    DOCTOR = 1 << 6
    ALL = (1 << 7) - 1


class Slot:
    PASSPHRASE = 1
    RECOVERY = 2


class Status:
    INITIALIZED = 1
    RECOVERY_CONFIRMED = 2
    UNLOCKED = 4


class KilixSecretsError(Exception):
    """Base class for a non-OK ``ksec_result``."""

    code = 9

    def __init__(self, message: str = "", code: int | None = None) -> None:
        self.code = int(self.code if code is None else code)
        super().__init__(message or f"kilix-secrets result {self.code}")


class Locked(KilixSecretsError):
    code = 1


class Denied(KilixSecretsError):
    code = 2


class NotFound(KilixSecretsError):
    code = 3


class Expired(KilixSecretsError):
    code = 4


class Invalid(KilixSecretsError):
    code = 5


class LimitExceeded(KilixSecretsError):
    code = 6


class IoError(KilixSecretsError):
    code = 7


class CryptoError(KilixSecretsError):
    code = 8


class ProtocolError(KilixSecretsError):
    code = 9


class Busy(KilixSecretsError):
    code = 10


class Exists(KilixSecretsError):
    code = 11


class AuditError(KilixSecretsError):
    code = 12


class OutOfMemory(KilixSecretsError):
    code = 13


class Conflict(KilixSecretsError):
    code = 14


_BY_CODE: dict[int, type[KilixSecretsError]] = {
    1: Locked,
    2: Denied,
    3: NotFound,
    4: Expired,
    5: Invalid,
    6: LimitExceeded,
    7: IoError,
    8: CryptoError,
    9: ProtocolError,
    10: Busy,
    11: Exists,
    12: AuditError,
    13: OutOfMemory,
    14: Conflict,
}


class _CField(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("value", ctypes.POINTER(ctypes.c_uint8)),
        ("value_len", ctypes.c_size_t),
    ]


class _CGrant(ctypes.Structure):
    _fields_ = [
        ("application_id", ctypes.c_char_p),
        ("verbs", ctypes.c_uint32),
    ]


class _CRecord(ctypes.Structure):
    _fields_ = [
        ("owner", ctypes.c_char_p),
        ("type", ctypes.c_char_p),
        ("label", ctypes.c_char_p),
        ("expires_at", ctypes.c_uint64),
        ("fields", ctypes.POINTER(_CField)),
        ("field_count", ctypes.c_size_t),
        ("grants", ctypes.POINTER(_CGrant)),
        ("grant_count", ctypes.c_size_t),
    ]


class _CIdentityInfo(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("vault_uuid", ctypes.c_uint8 * 16),
        ("record_id", ctypes.c_uint8 * RECORD_ID_BYTES),
        ("record_revision", ctypes.c_uint64),
        ("public_key", ctypes.c_uint8 * IDENTITY_KEY_BYTES),
        ("anchor", ctypes.c_uint8 * IDENTITY_ANCHOR_BYTES),
    ]


@dataclass
class Field:
    name: str
    value: bytes


@dataclass
class Grant:
    application_id: str
    verbs: int


@dataclass
class Record:
    owner: str
    type: str
    label: str
    expires_at: int = 0
    fields: list[Field] | None = None
    grants: list[Grant] | None = None

    def __post_init__(self) -> None:
        if self.fields is None:
            self.fields = []
        if self.grants is None:
            self.grants = []


@dataclass
class IdentityInfo:
    version: int
    vault_uuid: bytes
    record_id: bytes
    record_revision: int
    public_key: bytes
    anchor: bytes


@dataclass
class IdentityOpen:
    private_key: bytearray
    info: IdentityInfo
    lease_fd: int

    def close(self) -> None:
        zero(self.private_key)
        if self.lease_fd >= 0:
            os.close(self.lease_fd)
            self.lease_fd = -1


def zero(buf: bytearray) -> None:
    """Overwrite a caller-owned secret buffer."""
    if not isinstance(buf, bytearray):
        raise Invalid("zero expects a bytearray")
    for index in range(len(buf)):
        buf[index] = 0


_library_lock = threading.Lock()
_library: ctypes.CDLL | None = None
_library_key: object = None


def load_library() -> ctypes.CDLL:
    """Load ``libkilix-secrets``.

    ``KILIX_SECRETS_LIBRARY`` is a path and wins when it is set. Otherwise
    ``ctypes.util.find_library`` is used, then the soname
    ``libkilix-secrets.so.0``. A set environment variable is never replaced
    by a later fallback.
    """
    global _library, _library_key
    env = os.environ.get("KILIX_SECRETS_LIBRARY")
    if env is not None:
        key: object = ("env", env)
    else:
        key = ("search",)
    with _library_lock:
        if _library is not None and _library_key == key:
            return _library
        lib = _open_library(env)
        _configure(lib)
        _init_sodium(lib)
        _library = lib
        _library_key = key
        return lib


def _open_library(env: str | None) -> ctypes.CDLL:
    if env is not None:
        return ctypes.CDLL(env, use_errno=True)
    found = ctypes.util.find_library("kilix-secrets")
    if found:
        try:
            return ctypes.CDLL(found, use_errno=True)
        except OSError:
            pass
    return ctypes.CDLL("libkilix-secrets.so.0", use_errno=True)


def _init_sodium(lib: ctypes.CDLL) -> None:
    """``sodium_malloc`` aborts unless ``sodium_init`` has run.

    The client allocates secure memory on put, export, and rotation. The
    daemon does its own init; a fresh binding process has to as well.
    """
    init = getattr(lib, "sodium_init", None)
    if init is None:
        init = ctypes.CDLL("libsodium.so.23", use_errno=True).sodium_init
    init.argtypes = []
    init.restype = ctypes.c_int
    if init() < 0:
        raise CryptoError("libsodium could not be initialized")


def _configure(lib: ctypes.CDLL) -> None:
    void_p = ctypes.c_void_p
    u8_p = ctypes.POINTER(ctypes.c_uint8)
    lib.ksec_result_string.argtypes = [ctypes.c_int]
    lib.ksec_result_string.restype = ctypes.c_char_p
    lib.ksec_connect.argtypes = [ctypes.POINTER(void_p)]
    lib.ksec_connect.restype = ctypes.c_int
    lib.ksec_connect_at.argtypes = [ctypes.POINTER(void_p), ctypes.c_char_p, ctypes.c_int]
    lib.ksec_connect_at.restype = ctypes.c_int
    lib.ksec_client_free.argtypes = [void_p]
    lib.ksec_client_free.restype = None
    lib.ksec_supervisor_mint.argtypes = [
        ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_int),
    ]
    lib.ksec_supervisor_mint.restype = ctypes.c_int
    lib.ksec_supervisor_mint_scoped.argtypes = [
        ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32,
        u8_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_int),
    ]
    lib.ksec_supervisor_mint_scoped.restype = ctypes.c_int
    client = void_p
    lib.ksec_vault_init.argtypes = [client, ctypes.c_int, ctypes.c_int]
    lib.ksec_vault_init.restype = ctypes.c_int
    lib.ksec_unlock.argtypes = [client, ctypes.c_int, ctypes.c_int]
    lib.ksec_unlock.restype = ctypes.c_int
    lib.ksec_lock.argtypes = [client]
    lib.ksec_lock.restype = ctypes.c_int
    lib.ksec_change_passphrase.argtypes = [client, ctypes.c_int]
    lib.ksec_change_passphrase.restype = ctypes.c_int
    lib.ksec_rotate_master.argtypes = [client, ctypes.c_int, ctypes.c_int]
    lib.ksec_rotate_master.restype = ctypes.c_int
    lib.ksec_export_backup.argtypes = [client, ctypes.c_int, ctypes.c_int]
    lib.ksec_export_backup.restype = ctypes.c_int
    lib.ksec_import_backup.argtypes = [client, ctypes.c_int, ctypes.c_int]
    lib.ksec_import_backup.restype = ctypes.c_int
    lib.ksec_reset_vault.argtypes = [client, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    lib.ksec_reset_vault.restype = ctypes.c_int
    lib.ksec_put.argtypes = [client, ctypes.POINTER(_CRecord), u8_p]
    lib.ksec_put.restype = ctypes.c_int
    lib.ksec_replace.argtypes = [client, u8_p, ctypes.POINTER(_CRecord)]
    lib.ksec_replace.restype = ctypes.c_int
    lib.ksec_get_to_fd.argtypes = [client, u8_p, ctypes.c_char_p, ctypes.c_int]
    lib.ksec_get_to_fd.restype = ctypes.c_int
    lib.ksec_get_buf.argtypes = [
        client, u8_p, ctypes.c_char_p, u8_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.ksec_get_buf.restype = ctypes.c_int
    lib.ksec_identity_open.argtypes = [
        client, u8_p, u8_p, u8_p, ctypes.POINTER(_CIdentityInfo),
        ctypes.POINTER(ctypes.c_int),
    ]
    lib.ksec_identity_open.restype = ctypes.c_int
    lib.ksec_identity_info_get.argtypes = [
        client, u8_p, u8_p, ctypes.POINTER(_CIdentityInfo),
    ]
    lib.ksec_identity_info_get.restype = ctypes.c_int
    lib.ksec_delete.argtypes = [client, u8_p]
    lib.ksec_delete.restype = ctypes.c_int
    lib.ksec_list_to_fd.argtypes = [client, ctypes.c_int]
    lib.ksec_list_to_fd.restype = ctypes.c_int
    lib.ksec_show_to_fd.argtypes = [client, u8_p, ctypes.c_int]
    lib.ksec_show_to_fd.restype = ctypes.c_int
    lib.ksec_grant_record.argtypes = [client, u8_p, ctypes.c_char_p, ctypes.c_uint32]
    lib.ksec_grant_record.restype = ctypes.c_int
    lib.ksec_revoke_record.argtypes = [client, u8_p, ctypes.c_char_p]
    lib.ksec_revoke_record.restype = ctypes.c_int
    lib.ksec_doctor_to_fd.argtypes = [client, ctypes.c_int]
    lib.ksec_doctor_to_fd.restype = ctypes.c_int
    lib.ksec_compact.argtypes = [client]
    lib.ksec_compact.restype = ctypes.c_int
    lib.ksec_dataset_create.argtypes = [client, ctypes.c_char_p, u8_p]
    lib.ksec_dataset_create.restype = ctypes.c_int
    lib.ksec_seal_fd.argtypes = [
        client, u8_p, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_int, ctypes.c_int,
    ]
    lib.ksec_seal_fd.restype = ctypes.c_int
    lib.ksec_unseal_fd.argtypes = [
        client, u8_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint64),
    ]
    lib.ksec_unseal_fd.restype = ctypes.c_int
    lib.ksec_status.argtypes = [client, ctypes.POINTER(ctypes.c_uint32)]
    lib.ksec_status.restype = ctypes.c_int
    lib.ksec_watch.argtypes = [client, ctypes.POINTER(ctypes.c_int)]
    lib.ksec_watch.restype = ctypes.c_int


def result_string(code: int) -> str:
    lib = load_library()
    text = lib.ksec_result_string(int(code))
    if text is None:
        return "unknown result"
    return text.decode("utf-8", "replace")


def raise_for_result(code: int) -> None:
    if int(code) == 0:
        return
    exc_type = _BY_CODE.get(int(code), ProtocolError)
    raise exc_type(result_string(int(code)), int(code))


def require_text(value: object, label: str) -> str:
    """Reject a value ``c_char_p`` would truncate or refuse to encode."""
    if not isinstance(value, str):
        raise Invalid(f"{label} must be text")
    if "\x00" in value:
        raise Invalid("text contains a NUL")
    return value


def require_revision(value: object) -> int:
    """Reject a revision ``c_uint64`` would wrap."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise Invalid("revision must be a whole number")
    if value < 0 or value > _UINT64_MAX:
        raise Invalid("revision is out of range")
    return value


def max_sealed_dataset_bytes() -> int:
    """Upper bound of a sealed file for ``KSEC_MAX_DATASET_BYTES`` of plaintext."""
    chunks = (MAX_DATASET_BYTES + _DATASET_CHUNK_BYTES - 1) // _DATASET_CHUNK_BYTES
    prefix = _DATASET_PREFIX_FIXED_BYTES + MAX_APP_ID + MAX_DATASET_NAME
    return (
        prefix
        + _DATASET_STREAM_HEADER_BYTES
        + MAX_DATASET_BYTES
        + chunks * _DATASET_CHUNK_OVERHEAD
    )


MAX_SEALED_DATASET_BYTES = max_sealed_dataset_bytes()


def _id_array(record_id: bytes) -> ctypes.Array:
    if not isinstance(record_id, (bytes, bytearray)) or len(record_id) != RECORD_ID_BYTES:
        raise Invalid("record id must be 16 bytes")
    return (ctypes.c_uint8 * RECORD_ID_BYTES).from_buffer_copy(bytes(record_id))


def _anchor_array(anchor: bytes | None):
    if anchor is None:
        return None
    if not isinstance(anchor, (bytes, bytearray)) or len(anchor) != IDENTITY_ANCHOR_BYTES:
        raise Invalid("anchor must be 32 bytes")
    return (ctypes.c_uint8 * IDENTITY_ANCHOR_BYTES).from_buffer_copy(bytes(anchor))


def read_input_sealed_memfd(input_fd: int, maximum: int) -> int:
    """Copy ``input_fd`` through EOF into a sealed memfd. The caller closes it.

    The read stops at ``maximum`` bytes, the same rule as the C client's
    ``read_input_sealed_memfd``. The caller's descriptor is not read again.
    """
    if isinstance(input_fd, bool) or not isinstance(input_fd, int) or input_fd < 0:
        raise Invalid("input descriptor is invalid")
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
        raise Invalid("input limit is invalid")
    flags = os.MFD_CLOEXEC | getattr(os, "MFD_ALLOW_SEALING", 0)
    fd = os.memfd_create("ksec-dataset-request", flags)
    try:
        total = 0
        while True:
            try:
                chunk = os.read(input_fd, _DATASET_CHUNK_BYTES)
            except InterruptedError:
                continue
            except OSError as exc:
                raise IoError(os.strerror(exc.errno) if exc.errno else "I/O failure") from exc
            if not chunk:
                break
            if len(chunk) > maximum - total:
                raise LimitExceeded("limit exceeded")
            view = memoryview(chunk)
            offset = 0
            try:
                while offset < len(view):
                    try:
                        wrote = os.write(fd, view[offset:])
                    except InterruptedError:
                        continue
                    except OSError as exc:
                        raise IoError(
                            os.strerror(exc.errno) if exc.errno else "I/O failure") from exc
                    if wrote <= 0:
                        raise IoError("I/O failure")
                    offset += wrote
            finally:
                view.release()
            total += len(chunk)
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            import fcntl
            fcntl.fcntl(fd, _F_ADD_SEALS, _F_SEAL)
        except OSError as exc:
            raise IoError(os.strerror(exc.errno) if exc.errno else "I/O failure") from exc
    except Exception:
        os.close(fd)
        raise
    return fd


def secret_memfd(payload: bytes | bytearray) -> int:
    """A sealed read-only memfd holding ``payload``. The caller closes it."""
    if not isinstance(payload, (bytes, bytearray)):
        raise Invalid("secret must be bytes")
    flags = os.MFD_CLOEXEC
    allow = getattr(os, "MFD_ALLOW_SEALING", 0)
    fd = os.memfd_create("ksec-secret", flags | allow)
    try:
        view = memoryview(payload)
        offset = 0
        try:
            while offset < len(view):
                offset += os.write(fd, view[offset:])
        finally:
            view.release()
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            import fcntl
            fcntl.fcntl(fd, _F_ADD_SEALS, _F_SEAL)
        except OSError:
            pass
    except Exception:
        os.close(fd)
        raise
    return fd


def read_secret_fd(fd: int, limit: int = MAX_SECRET_BYTES) -> bytearray:
    """Read a memfd or file into a bytearray. Pipes are read until EOF."""
    try:
        size = os.fstat(fd).st_size
    except OSError as exc:
        raise IoError(os.strerror(exc.errno)) from exc
    if size < 0 or size > limit:
        raise LimitExceeded("descriptor exceeds the accepted size")
    if size == 0:
        # A pipe or an empty memfd. Read one buffer and refuse overflow.
        chunk = os.read(fd, limit + 1)
        if len(chunk) > limit:
            raise LimitExceeded("descriptor exceeds the accepted size")
        return bytearray(chunk)
    buf = bytearray(size)
    view = memoryview(buf)
    got = 0
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        while got < size:
            chunk = os.read(fd, size - got)
            if not chunk:
                break
            view[got:got + len(chunk)] = chunk
            got += len(chunk)
    except OSError as exc:
        zero(buf)
        raise IoError(os.strerror(exc.errno)) from exc
    finally:
        view.release()
    if got != size:
        zero(buf)
        raise IoError("short read from descriptor")
    extra = os.read(fd, 1)
    if extra:
        zero(buf)
        raise LimitExceeded("descriptor grew during the read")
    return buf


def _capture(call: Callable[[int], None], limit: int = MAX_SECRET_BYTES) -> bytearray:
    fd = os.memfd_create("ksec-out", os.MFD_CLOEXEC)
    try:
        call(fd)
        return read_secret_fd(fd, limit)
    finally:
        os.close(fd)


def _info_from_c(info: _CIdentityInfo) -> IdentityInfo:
    return IdentityInfo(
        version=int(info.version),
        vault_uuid=bytes(info.vault_uuid),
        record_id=bytes(info.record_id),
        record_revision=int(info.record_revision),
        public_key=bytes(info.public_key),
        anchor=bytes(info.anchor),
    )


def _build_record(record: Record) -> tuple[_CRecord, list[object]]:
    if record.fields is None or record.grants is None:
        raise Invalid("record fields are missing")
    keep: list[object] = []
    owner = require_text(record.owner, "owner").encode()
    kind = require_text(record.type, "type").encode()
    label = require_text(record.label, "label").encode()
    keep.extend((owner, kind, label))
    fields = (_CField * len(record.fields))()
    for index, field in enumerate(record.fields):
        name = require_text(field.name, "field name").encode()
        if len(field.value) == 0:
            raise Invalid("field value is empty")
        blob = (ctypes.c_uint8 * len(field.value)).from_buffer_copy(field.value)
        keep.append(name)
        keep.append(blob)
        fields[index].name = name
        fields[index].value = ctypes.cast(blob, ctypes.POINTER(ctypes.c_uint8))
        fields[index].value_len = len(field.value)
    grants = (_CGrant * len(record.grants))()
    for index, grant in enumerate(record.grants):
        app = require_text(grant.application_id, "application id").encode()
        keep.append(app)
        grants[index].application_id = app
        grants[index].verbs = int(grant.verbs)
    built = _CRecord()
    built.owner = owner
    built.type = kind
    built.label = label
    built.expires_at = int(record.expires_at)
    built.fields = ctypes.cast(fields, ctypes.POINTER(_CField)) if record.fields else None
    built.field_count = len(record.fields)
    built.grants = ctypes.cast(grants, ctypes.POINTER(_CGrant)) if record.grants else None
    built.grant_count = len(record.grants)
    keep.append(fields)
    keep.append(grants)
    keep.append(built)
    return built, keep


def _wipe_record_keep(keep: list[object]) -> None:
    for item in keep:
        if isinstance(item, ctypes.Array) and item._type_ is ctypes.c_uint8:
            ctypes.memset(item, 0, ctypes.sizeof(item))


class Client:
    """One activated connection. ``connect_at`` consumes ``capability_fd``."""

    def __init__(self, handle: ctypes.c_void_p) -> None:
        self._handle = handle
        self._lib = load_library()

    @classmethod
    def connect(cls) -> "Client":
        """``ksec_connect``: socket and capability fd come from the environment."""
        lib = load_library()
        holder = ctypes.c_void_p()
        raise_for_result(lib.ksec_connect(ctypes.byref(holder)))
        return cls(holder)

    @classmethod
    def connect_at(cls, socket_path: str, capability_fd: int) -> "Client":
        """``ksec_connect_at``. The capability descriptor is always consumed."""
        lib = load_library()
        try:
            encoded = os.fsencode(require_text(socket_path, "socket path"))
        except Invalid:
            if capability_fd >= 0:
                os.close(capability_fd)
            raise
        except (TypeError, ValueError, UnicodeError):
            if capability_fd >= 0:
                os.close(capability_fd)
            raise Invalid("socket path is invalid") from None
        holder = ctypes.c_void_p()
        raise_for_result(lib.ksec_connect_at(ctypes.byref(holder), encoded, int(capability_fd)))
        return cls(holder)

    def close(self) -> None:
        handle = self._handle
        self._handle = ctypes.c_void_p()
        if handle and handle.value:
            self._lib.ksec_client_free(handle)

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _ptr(self) -> ctypes.c_void_p:
        if self._handle is None or not self._handle.value:
            raise Invalid("client is closed")
        return self._handle

    def vault_init(self, passphrase: bytes | bytearray) -> bytearray:
        fd = secret_memfd(passphrase)

        def run(out: int) -> None:
            try:
                raise_for_result(self._lib.ksec_vault_init(self._ptr(), fd, out))
            finally:
                os.close(fd)

        return _capture(run, 1024)

    def unlock(self, slot: int, secret: bytes | bytearray) -> None:
        fd = secret_memfd(secret)
        try:
            raise_for_result(self._lib.ksec_unlock(self._ptr(), int(slot), fd))
        finally:
            os.close(fd)

    def lock(self) -> None:
        raise_for_result(self._lib.ksec_lock(self._ptr()))

    def change_passphrase(self, passphrase: bytes | bytearray) -> None:
        fd = secret_memfd(passphrase)
        try:
            raise_for_result(self._lib.ksec_change_passphrase(self._ptr(), fd))
        finally:
            os.close(fd)

    def rotate_master(self, passphrase: bytes | bytearray, recovery: bytes | bytearray) -> None:
        pass_fd = secret_memfd(passphrase)
        rec_fd = secret_memfd(recovery)
        try:
            raise_for_result(self._lib.ksec_rotate_master(self._ptr(), pass_fd, rec_fd))
        finally:
            os.close(pass_fd)
            os.close(rec_fd)

    def export_backup(self, passphrase: bytes | bytearray, output_fd: int) -> None:
        fd = secret_memfd(passphrase)
        try:
            raise_for_result(self._lib.ksec_export_backup(self._ptr(), fd, int(output_fd)))
        finally:
            os.close(fd)

    def import_backup(self, passphrase: bytes | bytearray, input_fd: int) -> None:
        fd = secret_memfd(passphrase)
        try:
            raise_for_result(self._lib.ksec_import_backup(self._ptr(), fd, int(input_fd)))
        finally:
            os.close(fd)

    def reset_vault(self, confirmation: str, passphrase: bytes | bytearray) -> bytearray:
        confirmed = require_text(confirmation, "confirmation").encode()
        fd = secret_memfd(passphrase)

        def run(out: int) -> None:
            try:
                raise_for_result(self._lib.ksec_reset_vault(
                    self._ptr(), confirmed, fd, out))
            finally:
                os.close(fd)

        return _capture(run, 1024)

    def put(self, record: Record) -> bytes:
        built, keep = _build_record(record)
        out = (ctypes.c_uint8 * RECORD_ID_BYTES)()
        try:
            raise_for_result(self._lib.ksec_put(self._ptr(), ctypes.byref(built), out))
            return bytes(out)
        finally:
            _wipe_record_keep(keep)

    def replace(self, record_id: bytes, record: Record) -> None:
        built, keep = _build_record(record)
        ident = _id_array(record_id)
        try:
            raise_for_result(self._lib.ksec_replace(self._ptr(), ident, ctypes.byref(built)))
        finally:
            _wipe_record_keep(keep)

    def get(self, record_id: bytes, field: str, max_len: int | None = None) -> bytearray:
        ident = _id_array(record_id)
        field_name = require_text(field, "field name").encode()
        if max_len is None:
            def run(out: int) -> None:
                raise_for_result(self._lib.ksec_get_to_fd(
                    self._ptr(), ident, field_name, out))
            return _capture(run, MAX_SECRET_BYTES)
        if max_len <= 0 or max_len > MAX_SECRET_BYTES:
            raise Invalid("get buffer length is out of range")
        buf = (ctypes.c_uint8 * max_len)()
        got = ctypes.c_size_t(0)
        try:
            raise_for_result(self._lib.ksec_get_buf(
                self._ptr(), ident, field_name, buf, max_len, ctypes.byref(got)))
            return bytearray(ctypes.string_at(buf, got.value))
        finally:
            ctypes.memset(buf, 0, max_len)

    def get_to_fd(self, record_id: bytes, field: str, output_fd: int) -> None:
        raise_for_result(self._lib.ksec_get_to_fd(
            self._ptr(), _id_array(record_id),
            require_text(field, "field name").encode(), int(output_fd)))

    def identity_open(self, record_id: bytes, expected_anchor: bytes | None = None) -> IdentityOpen:
        ident = _id_array(record_id)
        anchor = _anchor_array(expected_anchor)
        key = (ctypes.c_uint8 * IDENTITY_KEY_BYTES)()
        info = _CIdentityInfo()
        lease = ctypes.c_int(-1)
        try:
            raise_for_result(self._lib.ksec_identity_open(
                self._ptr(), ident, anchor, key, ctypes.byref(info), ctypes.byref(lease)))
            private = bytearray(ctypes.string_at(key, IDENTITY_KEY_BYTES))
            return IdentityOpen(private, _info_from_c(info), int(lease.value))
        finally:
            ctypes.memset(key, 0, IDENTITY_KEY_BYTES)
            ctypes.memset(ctypes.byref(info), 0, ctypes.sizeof(info))

    def identity_info(self, record_id: bytes, expected_anchor: bytes | None = None) -> IdentityInfo:
        info = _CIdentityInfo()
        try:
            raise_for_result(self._lib.ksec_identity_info_get(
                self._ptr(), _id_array(record_id), _anchor_array(expected_anchor),
                ctypes.byref(info)))
            return _info_from_c(info)
        finally:
            ctypes.memset(ctypes.byref(info), 0, ctypes.sizeof(info))

    def delete(self, record_id: bytes) -> None:
        raise_for_result(self._lib.ksec_delete(self._ptr(), _id_array(record_id)))

    def list(self) -> bytes:
        def run(out: int) -> None:
            raise_for_result(self._lib.ksec_list_to_fd(self._ptr(), out))
        body = _capture(run, MAX_SECRET_BYTES + 4096)
        try:
            return bytes(body)
        finally:
            zero(body)

    def show(self, record_id: bytes) -> bytes:
        ident = _id_array(record_id)

        def run(out: int) -> None:
            raise_for_result(self._lib.ksec_show_to_fd(self._ptr(), ident, out))
        body = _capture(run, 8192)
        try:
            return bytes(body)
        finally:
            zero(body)

    def grant(self, record_id: bytes, application_id: str, verbs: int) -> None:
        raise_for_result(self._lib.ksec_grant_record(
            self._ptr(), _id_array(record_id),
            require_text(application_id, "application id").encode(), int(verbs)))

    def revoke(self, record_id: bytes, application_id: str) -> None:
        raise_for_result(self._lib.ksec_revoke_record(
            self._ptr(), _id_array(record_id),
            require_text(application_id, "application id").encode()))

    def doctor(self) -> bytes:
        def run(out: int) -> None:
            raise_for_result(self._lib.ksec_doctor_to_fd(self._ptr(), out))
        body = _capture(run, 4096)
        try:
            return bytes(body)
        finally:
            zero(body)

    def compact(self) -> None:
        raise_for_result(self._lib.ksec_compact(self._ptr()))

    def dataset_create(self, label: str) -> bytes:
        out = (ctypes.c_uint8 * RECORD_ID_BYTES)()
        raise_for_result(self._lib.ksec_dataset_create(
            self._ptr(), require_text(label, "label").encode(), out))
        return bytes(out)

    def seal_fd(self, record_id: bytes, dataset_name: str, revision: int,
                input_fd: int, output_fd: int) -> None:
        raise_for_result(self._lib.ksec_seal_fd(
            self._ptr(), _id_array(record_id),
            require_text(dataset_name, "dataset name").encode(),
            require_revision(revision), int(input_fd), int(output_fd)))

    def unseal_fd(self, record_id: bytes, dataset_name: str,
                  input_fd: int, output_fd: int) -> int:
        revision = ctypes.c_uint64(0)
        raise_for_result(self._lib.ksec_unseal_fd(
            self._ptr(), _id_array(record_id),
            require_text(dataset_name, "dataset name").encode(),
            int(input_fd), int(output_fd), ctypes.byref(revision)))
        return int(revision.value)

    def status(self) -> int:
        flags = ctypes.c_uint32(0)
        raise_for_result(self._lib.ksec_status(self._ptr(), ctypes.byref(flags)))
        return int(flags.value)

    def watch(self) -> int:
        fd = ctypes.c_int(-1)
        raise_for_result(self._lib.ksec_watch(self._ptr(), ctypes.byref(fd)))
        return int(fd.value)


def mint_for_child(socket_path: str, pid: int, app_id: str, verbs: int,
                   lifetime: int, record_id: bytes | None = None) -> int:
    """Mint a capability for a child of this process. Returns the descriptor."""
    lib = load_library()
    out = ctypes.c_int(-1)
    encoded_socket = os.fsencode(require_text(socket_path, "socket path"))
    encoded_app = require_text(app_id, "application id").encode()
    if record_id is None:
        raise_for_result(lib.ksec_supervisor_mint(
            encoded_socket, int(pid), encoded_app,
            int(verbs), int(lifetime), ctypes.byref(out)))
    else:
        raise_for_result(lib.ksec_supervisor_mint_scoped(
            encoded_socket, int(pid), encoded_app, int(verbs),
            _id_array(record_id), int(lifetime), ctypes.byref(out)))
    if out.value < 0:
        raise ProtocolError("mint returned no capability descriptor")
    return int(out.value)


def connect(socket_path: str | None = None, capability_fd: int | None = None) -> Client:
    if socket_path is None and capability_fd is None:
        return Client.connect()
    if socket_path is None or capability_fd is None:
        raise Invalid("connect requires both a socket path and a capability descriptor")
    return Client.connect_at(socket_path, capability_fd)
