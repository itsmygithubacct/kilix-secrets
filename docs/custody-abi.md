# F113 custody ABI

This section was moved verbatim from the README. The full consumer contract
is [F113-CUSTODY-INTERFACE.md](F113-CUSTODY-INTERFACE.md); the declarations
are in [`include/kilix_secrets.h`](../include/kilix_secrets.h).

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
