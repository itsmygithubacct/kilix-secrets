# Threat model

## Protected cases

The locked vault is designed to protect secret values and encrypted metadata
from offline inspection of the data directory, backups, or copied vault files.
The daemon rejects a different UID, unsafe filesystem objects, malformed or
oversized protocol messages, unauthenticated records, revision discontinuity,
and unknown format or algorithm identifiers. It avoids secret values in argv,
the environment, ordinary socket replies, logs, paths, and temporary files.
Encrypted exports use a fresh salt and nonces and authenticate the complete
source header and journal. Restore verifies the entire envelope, inner header,
and journal before atomically replacing anything; the displaced encrypted or
damaged directory is retained.

Cross-application grants deny by default, are encrypted and authenticated with
the owning record, are bounded at 16/16 entries, and are checked dynamically.
Only the owner can change them; narrowing or revocation affects the next
authorization and cannot silently create a replacement secret.

F113 device-identity records have a narrower rule: exactly one 32-byte private
field, exclusive `kilix-pairingd` ownership, no expiry, and 0/16 grants.
Generic read/use delivery is refused. The dedicated identity-open operation
derives public metadata, verifies an optional expected generation anchor, and
couples plaintext delivery to one of 128/128 bounded pollable leases. Lock,
identity replacement/deletion, generation publication, capability/process
loss, disconnect and daemon termination close the lease so the consumer can
wipe its locked buffer and fail closed.
The separate public-info operation derives the same key and anchor without
copying private bytes into the consumer and creates 0/128 leases; it remains
vault- and capability-gated because metadata can still identify a device.

The daemon has one event-loop thread, a fixed 64/64-connection table, and no
application worker queue. It processes at most one framed request per ready
connection per poll iteration and closes newly accepted connections when all
64/64 slots are occupied. The load harness fills 64/64 slots, drives
4,096/4,096 bounded requests, requires 16/16 overflow connections to close,
and caps the daemon's observed RSS increase at 8,192/8,192 KiB.

The daemon connects to the authenticated system bus, inventories graphical
sessions for its UID, and treats an authenticated `Lock`, `LockedHint=true`, or
tracked-session teardown as a global lock. A remote/headless session cannot
suppress that transition, and no session event unlocks the vault. Monitor
parsing or bus failure locks custody and terminates the daemon. The isolated
test bus also proves that a same-UID sender which does not own
`org.freedesktop.login1` cannot inject a qualifying event.

## Honest limits

The design does not protect an unlocked secret from root, a compromised kernel,
code injected into the daemon or intended consumer, or malware already running
with the user's full session authority. A hostile same-UID process can trace a
cooperating process or alter user-owned startup state. Capability policy is a
cooperative boundary that prevents accidental cross-application use; it is not
a sandbox.

Memory locking and explicit clearing reduce exposure but do not make memory
forensics impossible. Clipboard managers, terminal scrollback, screenshots,
and consuming-application behavior are outside the vault's control. Replacing
the complete portable vault with an older valid copy while the daemon is
stopped may be undetectable; no trusted rollback counter is claimed.
Importing an older valid backup is an explicit rollback and does not create
monotonicity across reboot or restore.

The identity anchor detects a mismatch between the live vault identity and an
independently retained expected anchor. It cannot detect a coherent rollback
that restores both the vault and the consumer's expected-anchor/peer state to
the same older version. A lease revokes future authorization and signals the
consumer; it cannot erase plaintext already copied into a compromised or
non-cooperating process. `kilix-pairingd` must therefore keep that buffer locked
and clear it on every close/error path. F112 never supplies the key or lease
descriptor to the multiplexer.

There is no recovery backdoor. Losing every valid key slot loses the data.
Destructive reset is therefore an explicit loss-of-identity action, not a
recovery bypass: it requires the literal confirmation token, retains the old
encrypted directory indefinitely for separately authorized handling, creates a
new UUID, and requires all peers to revoke or re-pair.

Clipboard copy is opt-in and uses the active Kitty clipboard provider. Secret
bytes travel on provider standard input, never argv or environment. Timed
clearing occurs only after byte-exact read-back still matches; clipboard
history and another client's retained copy cannot be erased or guaranteed.
