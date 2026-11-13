# kilix-secrets

`kilix-secrets` is the local credential-vault provider for Kilix. It consists
of a per-user daemon, a C11 client library, and an administrative CLI. Secret
values are encrypted in an authenticated append-only journal and are delivered
to authorized consumers through descriptors, not command arguments or
environment variables.

This repository is the Plebian OS / Kilix F112 credential vault. Design review
A112 accepted the frozen design package. Independent implementation Review B
accepted the measured H0 production point in c7c5ebd. Publication of that
history on this repository's main branch is authorized. A release tag is a
separate act and is not authorized by this record.

The production daemon uses the H0 Argon2id point selected from
`docs/H0-CALIBRATION.txt`: 4 operations and 512 MiB. That corner's slowest
trial was 1734.0 ms, 266 ms under the 2000 ms ceiling. `doctor` reports
`kdf_point=production:ops=4,mem=512MiB`. The development KDF flags remain for
tests and mark the point `development`. The installed unit does not pass them.
Every start has either that compiled-in point or a paired development
override. Init and reset use the point configured for that process.

## Build

The build requires the Debian 13 `libsodium-dev` package matching runtime
`libsodium23` 1.0.18-1+deb13u1 and `libsystemd-dev` matching runtime
`libsystemd0` 257.13-1~deb13u1. See `docs/DEPENDENCIES.md` and
`THIRD_PARTY_NOTICES.md` for the exact local SBOM and licence evidence.

```sh
make
make test
make sanitize
make deb TEST_TMPDIR=/path/to/private-scratch
make deb-test TEST_TMPDIR=/path/to/private-scratch
```

Packagers may override `SODIUM_CPPFLAGS` and `SODIUM_LDLIBS` when building
against an unpacked, independently verified sysroot.
`make deb` produces a reproducible, source-bound Debian package in `dist/` and
refuses a dirty source tree. `make deb-test` additionally exercises dpkg
install, upgrade, rollback, remove, reinstall, and purge in an isolated root;
package removal and purge preserve user vault data.

The administrative CLI includes `init`, `unlock`, `lock`, `passwd`, `add`,
`replace`, `get`, `show`, `grant`, `revoke`, `copy`, `run`, `list`,
`dataset-create`, `seal`, `unseal`, `status`, `delete`, `rotate`, `export`,
`import`, `compact`, and `doctor`. Destructive record deletion requires the
exact form `delete RECORD --confirm RECORD`. `get` writes a field only to a
new 0600 file (`--output FILE`) or a descriptor (`--output-fd N`), never to a
terminal. `replace RECORD --field NAME` replaces the record's fields with that
one field and keeps its type, label, expiry and grants. `add` and `replace`
strip trailing CR and LF bytes from the value unless given `--raw`.
Backup output is encrypted-only, is created as a new 0600 file, and is never
silently overwritten. Import verifies the complete artifact, retains the
displaced generation, then locks the vault. Restoring an older valid artifact
is an explicit rollback; the portable backend has no trusted rollback counter.
Destructive vault reset requires the literal confirmation
`RESET-VAULT-AND-LOSE-IDENTITY`, creates a new vault UUID, retains the displaced
encrypted directory without automatic expiry, and requires recovery proof
before the new identity can unlock. Every peer must then be revoked or re-paired.

## F113 custody ABI

`ksec_identity_open` is the only production retrieval path for an F113 device
identity. The record is owned by `kilix-pairingd`, has type
`device-identity`, contains exactly one `private-key` field of exactly 32
bytes, has no expiry and permits 0/16 grants. Generic `get` and grant operations
are refused for this record class.

`ksec_identity_info_get` returns only the derived public key and stable anchor
through a sealed metadata descriptor; it delivers 0/1 private keys and creates
0/128 leases. It is the pairing daemon's public-identity access path. Other
processes, including the multiplexer, obtain public identity through F113's own
authorized IPC rather than connecting to F112.

The call atomically copies the raw X25519 private key into a caller-owned
32-byte buffer, derives and returns the 32-byte public identity, returns a
versioned stable anchor, and leaves a pollable lease descriptor. The caller
must put the private buffer in locked memory before the call, clear it on every
exit, keep the vault connection open, and terminate dependent operations when
the lease reports `POLLHUP`, `POLLERR`, or EOF. This is plaintext delivery to
the pairing daemon, not a sealed descriptor and not a signing/DH oracle. The
multiplexer receives 0/1 private keys and 0/1 F112 lease descriptors; pairingd
must translate invalidation into its own public-key/opaque-operation closure.

The stable anchor binds `KSECID01`, vault UUID, record ID, record revision and
derived public key. Passphrase rewrap and master-key re-encryption preserve it;
key replacement changes it. Import always closes live leases, after which an
exact matching backup reopens under the same anchor and a mismatched generation
returns `KSEC_ERR_CONFLICT`. Lock, delete, key replacement, master rotation,
import, reset, capability/process expiry, connection loss and daemon exit close
the relevant lease. The portable coherent-rollback limit still applies.

## Sealed datasets

An application that needs more than a few records keeps its own encrypted
file, and the vault holds only the key. `ksec_dataset_create` makes a
dataset-key record (object type 4) owned by the calling application: 32 bytes
the daemon generates, never returns, never replaces and never grants.
`ksec_seal_fd` and `ksec_unseal_fd` send up to 64 MiB through sealed memfds;
the daemon encrypts or decrypts under that key and returns a sealed memfd.
The client writes the output descriptor only after the daemon reports
success. The caller writes to a temporary file and renames it.

A sealed file (`KSDSET01`) names its vault, key record, owner, dataset name,
revision and exact length, and authenticates all of them on every chunk. A
file from another vault, key, owner or name is a `KSEC_ERR_CONFLICT`; any
damage, truncation or extension fails. The format does not prevent rollback:
an older file of the same dataset still opens and reports its older revision,
so the application compares revisions itself. Deleting the key record or
resetting the vault makes every file sealed under it unreadable. A daemon
older than this change refuses to unlock a vault that holds a dataset key.

`ksec_status` reports initialized, recovery-confirmed and unlocked without a
verb and works while locked. `ksec_watch` returns a descriptor the daemon
hangs up when the vault locks, the master key rotates, a backup is imported,
the vault is reset, the asking capability expires or disconnects, or the
daemon stops; the application then asks STATUS on a fresh capability.

CLI: `dataset-create --label LABEL`;
`seal RECORD --name NAME --revision N --input FILE|- --output FILE|-`;
`unseal RECORD --name NAME --input FILE|- --output FILE|-` (prints
`revision=N` on stderr); `status`.

See `docs/SEALED-DATASETS.md`, `docs/PROTOCOL.md` and `docs/VAULT-FORMAT.md`.

## Python binding

`python/kilix_secrets` is a standard-library ctypes binding for Python 3.11
and newer, installed to `lib/python3/dist-packages` and shipped in the
package. `Session` runs vault calls in a worker child process that holds the
capability and is renewed before the capability expires. `Watcher` keeps a
`WATCH` open and calls back when the vault locks. `seal_file` and
`unseal_file` publish atomically. See `docs/PYTHON.md`.

## Security boundary

The daemon protects a locked vault against offline inspection and refuses
malformed storage, protocol, and policy state. Application capabilities reduce
accidental cross-application disclosure among cooperating same-UID programs.
They do not contain root, a compromised kernel, injected daemon code, or a
hostile process that already controls the user's session. Portable whole-file
rollback while the daemon is stopped can be undetectable.

Sealed datasets keep this boundary. While the vault is unlocked, any process
that can act as the owning application can seal and unseal its files.

See `docs/THREAT-MODEL.md`, `docs/VAULT-FORMAT.md`,
`docs/F113-CUSTODY-INTERFACE.md`, `docs/SEALED-DATASETS.md`, and `SECURITY.md`
before using or reviewing the code.
