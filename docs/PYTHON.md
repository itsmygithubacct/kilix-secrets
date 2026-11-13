# Python binding

Standard-library ctypes binding for Python 3.11 and newer. It covers every
public function in `include/kilix_secrets.h`. Secrets and passphrases cross
into C through memfds. `get` returns a `bytearray` the caller can wipe with
`zero`.

## Library lookup

`KILIX_SECRETS_LIBRARY`, when set, is the library path. A set value is never
replaced by a fallback, including when that path cannot be loaded. Otherwise
the binding uses `ctypes.util.find_library("kilix-secrets")`, then the soname
`libkilix-secrets.so.0`.

Loading the library calls `sodium_init`. The client allocates secure memory
on put, export, and rotation, and `sodium_malloc` aborts if that init has
not run. The daemon initializes libsodium itself; a fresh binding process
does not inherit that.

## Calling the vault

`connect(socket_path, capability_fd)` activates a connection and consumes the
capability descriptor. `connect()` with no arguments uses the process
environment (`KILIX_SECRETS_SOCKET`, `KILIX_SECRETS_CAP_FD`, and a runtime
directory). `mint_for_child(socket_path, pid, app_id, verbs, lifetime,
record_id=None)` mints a capability for a child of this process. The socket
path is required so a mint cannot fall through to the per-user daemon.

`Result` holds the integer codes (`Result.LOCKED == 1`). Each code has an
exception: `Locked`, `Denied`, `NotFound`, `Expired`, `Invalid`,
`LimitExceeded`, `IoError`, `CryptoError`, `ProtocolError`, `Busy`, `Exists`,
`AuditError`, `OutOfMemory`, and `Conflict`. `OutOfMemory` is the binding's
name for result 13 so it does not shadow the builtin `MemoryError`.
`Verb`, `Slot`, and `Status` hold the flag values.

## Session

`Session(socket_path, app_id, verbs, lifetime=300, record_id=None)` spawns
`[sys.executable, "-m", "kilix_secrets.worker"]` over a `socketpair`, mints a
capability for that child, and passes the descriptor with `SCM_RIGHTS`.
Frames are length-prefixed JSON. Bytes are base64. Descriptors travel with
the frame. The worker refuses an unknown method. It is spawned from a thread
the session keeps until that worker is closed, so the worker keeps running
after the caller thread exits. It exits when the session closes it or the
parent process dies.

The session is safe to call from several threads. It replaces the worker
before the capability lifetime ends, and on `EXPIRED` (or a denial once that
window has closed) it replaces the worker and retries the call once. `lock`,
`rotate_master`, `import_backup`, and `reset_vault` clear the capability, so
the session starts a new worker before returning.

`seal_fd` and `unseal_fd` read the caller's input once into a sealed memfd.
Every attempt, including a retry, duplicates that memfd from offset 0. A
retry does not read the caller's descriptor again.

A text argument that contains a NUL, and a revision outside 0 through
2^64-1, raises `Invalid` before the C library is called.

## Watcher

`Watcher(socket_path, app_id, callback, lifetime=30, verbs=Verb.READ)` holds
a `WATCH` and renews it before the capability lifetime ends. `callback(status)`
runs once when the vault is observed locked. A renewal does not call it.
`renewals` counts those renewals.

## Sealing files

`seal_file` and `unseal_file` publish through an unnamed file in the target's
directory (mode 0600). After the write and `fsync`, the inode is linked by
`link` of `/proc/self/fd/N` into that directory (the portable `O_TMPFILE`
form). If the name already exists, the link uses a private name and `rename`
replaces the target. On failure the target is unchanged and any staged name
is removed. A crash before the link leaves no directory entry, so a killed
writer cannot replace the target or leave a plaintext temporary.

## Install

`make install` copies the package to
`$(DESTDIR)$(PREFIX)/lib/python3/dist-packages/kilix_secrets`.

## Tests

`tests/test_python_binding.py` drives a private daemon, the same way
`tests/test_integration.py` does. It checks each wrapped call, capability
expiry, the watcher, a killed `seal_file`, worker parent-death and unknown
methods, a seal retried from a slow pipe, worker lifetime across threads,
rejected names and revisions, and library lookup.
