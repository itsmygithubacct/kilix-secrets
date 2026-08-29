# kilix-secrets

`kilix-secrets` is the local credential-vault provider for Kilix. It consists
of a per-user daemon, a C11 client library, and an administrative CLI. Secret
values are encrypted in an authenticated append-only journal and are delivered
to authorized consumers through descriptors, not command arguments or
environment variables.

This repository is an unqualified local implementation candidate for Plebian
OS / Kilix 0.2.1 F112. Design review A112 accepted the frozen design package;
independent implementation Review B and shared-repository integration remain
mandatory. No remote, push, tag, or publication is authorized.

The production service intentionally has no development KDF flags. A final
Argon2id point remains externally unselected until it is calibrated on the H0
4 GiB target; initialization without that selection fails closed.

## Build

The build requires the Debian 13 `libsodium-dev` package matching runtime
`libsodium23` 1.0.18-1+deb13u1 and `libsystemd-dev` matching runtime
`libsystemd0` 257.13-1~deb13u1. See `docs/DEPENDENCIES.md` and
`THIRD_PARTY_NOTICES.md` for the exact local SBOM and licence evidence.

```sh
make
make test
make sanitize
```

Packagers may override `SODIUM_CPPFLAGS` and `SODIUM_LDLIBS` when building
against an unpacked, independently verified sysroot.

The administrative CLI includes `init`, `unlock`, `lock`, `passwd`, `add`,
`show`, `grant`, `revoke`, `copy`, `run`, `list`, `delete`, `rotate`, `export`,
`import`, `compact`, and `doctor`. Destructive record deletion requires the
exact form `delete RECORD --confirm RECORD`.
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

## Security boundary

The daemon protects a locked vault against offline inspection and refuses
malformed storage, protocol, and policy state. Application capabilities reduce
accidental cross-application disclosure among cooperating same-UID programs.
They do not contain root, a compromised kernel, injected daemon code, or a
hostile process that already controls the user's session. Portable whole-file
rollback while the daemon is stopped can be undetectable.

See `docs/THREAT-MODEL.md`, `docs/VAULT-FORMAT.md`,
`docs/F113-CUSTODY-INTERFACE.md`, and `SECURITY.md` before using or reviewing
the code.
