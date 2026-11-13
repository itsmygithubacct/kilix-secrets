# Local protocol v1

The daemon uses a per-user `SOCK_SEQPACKET` Unix socket. Every packet begins
with a fixed header containing the protocol version, operation, flags, request
identifier, and bounded payload length. Truncation, trailing bytes, unknown
operations, and unknown flags are refused.

The v1 operation registry has 27/27 defined operation IDs: capability
activation/minting; vault initialization, unlock and lock; create, replace,
read, confirmed delete, list and metadata-only show; doctor and compaction;
passphrase-slot change and master-key rotation; encrypted backup export/import;
grant/revoke; destructive vault reset; atomic F113 identity open;
public-only F113 identity info; dataset-key create, seal and unseal; and
status and watch. Unknown IDs fail closed.
Passphrase change uses the same dedicated-descriptor rule as initialization and
unlock; its general packet contains only a zero selector.

Delete carries exactly two consecutive copies of the 16-byte record ID. The
daemon compares them in constant time and refuses a missing or mismatched
confirmation before authorization, audit, or storage mutation. The
administrative CLI separately requires `delete RECORD --confirm RECORD`; a
programmatic `ksec_delete` call is itself the caller's explicit confirmation.

Show carries exactly one 16-byte record ID and returns a dedicated descriptor
containing only bounded metadata. Grant carries the record ID, a big-endian
32-bit grantable-verb mask, a big-endian 16-bit application-ID length, and the
canonical application ID. Revoke omits the verb mask. Grant and revoke are
owner-only mutations; the daemon rechecks the stored grant on every use.

Master-key rotation carries a zero selector and one sealed descriptor framed as
two big-endian 32-bit lengths followed by the current passphrase and recovery
secret. Both slots must independently unwrap the currently held master key.
The operation publishes a verified replacement generation, clears the old
master, and invalidates every capability.

Encrypted export carries a zero selector and a dedicated backup-passphrase or
recovery-secret descriptor. Its successful response contains one sealed
descriptor holding the complete backup artifact. Import carries a zero selector
and a sealed descriptor containing a big-endian 32-bit secret length, that
secret, and the bounded backup bytes. The daemon authenticates and decrypts the
complete artifact before staging any storage mutation. A successful import
globally locks the daemon and invalidates every capability.

Reset carries exactly the 29 ASCII bytes
`RESET-VAULT-AND-LOSE-IDENTITY` and a dedicated new-passphrase descriptor. Its
response descriptor contains the new 64-byte recovery rendering. The daemon
stages and verifies a generation-1 header under a fresh vault UUID, atomically
exchanges it with the current directory, retains the displaced encrypted or
damaged directory under `.vault-reset-retained-*`, globally locks, and requires
recovery proof before activation. A missing or non-exact confirmation is
refused before audit or mutation.

Identity open carries either exactly one 16-byte record ID, to accept the
current generation during explicit provisioning/recovery, or that ID followed
by an exact 32-byte expected anchor. The target must be an unexpired,
grant-free record owned by `kilix-pairingd`, with type `device-identity` and
exactly one 32-byte `private-key` field. Only a live `use` capability scoped to
that record is accepted. Generic get and grant/revoke paths refuse this object
class.

The successful response passes one descriptor containing exactly one 144-byte
frame before it becomes a pollable lease. The frame is: `KSID` magic (4),
big-endian frame version 1 (2), big-endian frame length 144 (2), vault UUID
(16), record ID (16), big-endian record revision (8), derived X25519 public key
(32), stable anchor (32), and raw X25519 private key (32). The library validates
the frame, independently re-derives the public key and anchor, copies the raw
private key into the caller's already-locked exact-length buffer, consumes all
144/144 bytes, and returns the now-empty descriptor as nonblocking and
close-on-exec.

The anchor is unkeyed BLAKE2b-256 over exactly the 80-byte sequence
`KSECID01 || vault_uuid || record_id || be64(record_revision) || public_key`.
It deliberately excludes the authenticated vault-header generation, so slot
rewrap and master-key re-encryption preserve identity. Record replacement,
including local-key rotation, advances the record revision and changes the
anchor. A supplied expected-anchor mismatch returns
`KSEC_ERR_CONFLICT` and creates 0/1 leases.

There are at most 128/128 identity leases. The daemon closes a lease writer on
global lock, matching-record replacement or deletion, master rotation, backup
import, destructive reset, capability expiry, target/supervisor death, client
disconnect, storage failure that forces lock, or daemon stop/failure. The
client observes `POLLHUP`/`POLLERR`/EOF and must immediately wipe the private
key and invalidate every dependent operation. Passphrase-slot rewrap,
compaction and backup export do not close a lease because they preserve the
active record and anchor. Import closes even when the restored anchor is
identical; the caller must reconnect, re-authorize and compare it again. The
lease carries no reason code, so the caller reopens or queries ordinary status
to distinguish locked, missing and conflicting state.

Identity info accepts the same 16/48-byte request and applies the same schema,
capability and expected-anchor checks. It returns a sealed descriptor holding
only the first 112/144 identity-frame bytes under magic `KSIP`: version/length,
vault UUID, record ID, revision, public key and anchor. It returns 0/1 private
keys and creates 0/128 leases. `kilix-pairingd` may cache this non-secret result,
but locked/unavailable custody still makes pairing operations unavailable; the
multiplexer obtains permitted public identity through F113 IPC, not this F112
socket.

Capabilities, passphrases, recovery material, records, metadata listings, and
secret replies travel on dedicated descriptors. General socket packets carry
only bounded routing metadata. All descriptors are close-on-exec unless a
supervisor deliberately passes one capability descriptor to its exact child.
The identity descriptor is the sole combined delivery/lease exception: its
fixed initial frame contains the private key and is consumed inside the client
library before the descriptor is returned to the caller.

## Sealed dataset operations 23–25

`DATASET_CREATE` (23), `SEAL` (24) and `UNSEAL` (25) move plaintext that is
too large for a vault record. The frozen contract is `docs/SEALED-DATASETS.md`
sections 2–5. Integers are big-endian. Each operation needs an activated
capability. A short, long, or trailing payload is a protocol failure when the
fixed part is malformed, and invalid input when a field value is out of range.

`DATASET_CREATE` carries a big-endian u16 label length and the label, and no
descriptor. An unexpected descriptor is a protocol failure. The label follows
ordinary label rules. Checks run in this order: payload grammar, the vault is
unlocked, `create` is authorized for the capability's own application id, then
the live record count is below 1,024. The daemon draws the 32 key bytes with
`randombytes_buf` into secure memory. The client cannot supply them. The record
is object type 4, type `dataset-key`, expiry 0, no grants, and exactly one
32-byte field named `dataset-key`. The response is the 16-byte record ID and
no descriptor. The audit events are `dataset-create` with outcomes `begin`
and `ok`, naming that record ID and no key bytes.

`SEAL` carries the 16-byte record ID, a big-endian u64 application revision,
a big-endian u16 name length, and the name. `UNSEAL` carries the 16-byte
record ID, a big-endian u16 name length, and the name. Both require one
request descriptor. A missing descriptor is a protocol failure. The descriptor
must already be a memfd whose `F_GET_SEALS` mask includes `F_SEAL_WRITE`,
`F_SEAL_GROW` and `F_SEAL_SHRINK`. A pipe, a regular file, an unsealed memfd,
or any other descriptor is invalid input. Seals are checked before size. Size
comes from `fstat`, and the daemon reads with `pread` from offset 0. `SEAL`
accepts a plaintext of 0 through 64 MiB; anything larger exceeds the limit.
`UNSEAL` accepts a sealed file no larger than the sealed length of a 64 MiB
plaintext with a 64-byte owner and a 128-byte name; anything larger exceeds
the limit. A length that is not the exact sealed length is invalid input.

Checks for both operations then run in this order: payload grammar, descriptor
present, vault unlocked, record present and not deleted, `use` authorized on
that record, and the record is a valid dataset key. A missing or deleted
record is not found. A failed `use` check is denied. Anything that is not a
dataset key is invalid input. Only after those checks come the descriptor
seals and size, the `seal` or `unseal` audit outcome `begin`, the crypto, and
the audit outcome `ok`. The audit line carries the record ID. It does not
carry key bytes, plaintext, or the dataset name. Neither operation changes
the store or any filesystem path. If the `ok` audit cannot be written, the
reply descriptor is discarded.

A successful `SEAL` reply has an empty payload and one daemon-made memfd of
the sealed file. A successful `UNSEAL` reply has a big-endian u64 revision
and one daemon-made memfd of the plaintext. Both reply memfds are sealed with
`F_SEAL_SEAL`, `F_SEAL_SHRINK`, `F_SEAL_GROW` and `F_SEAL_WRITE`, and rewound
to offset 0, before the reply is sent. Any failure returns no descriptor.
`UNSEAL` compares the file's vault UUID, key record ID, owner and name with
the vault and the request; a mismatch is an identity generation conflict.
An authentication failure, a wrong tag sequence, or a missing final tag is
an authentication failure.

PUT and REPLACE refuse object type 4 as invalid input. They also refuse any
record whose type string is `dataset-key`, whatever object type the client
claims. REPLACE of an existing type-4 record is denied before the replacement
body is read, including for the owner. GET of any field of a type-4 record is
denied before authorization. GRANT and REVOKE on a type-4 record are denied.

The client reads its input descriptor to end of file into a sealed memfd of
its own, inside the same size limits, and copies the reply descriptor to the
output descriptor only after the daemon has returned success and the response
payload has the expected length (none for `SEAL`, 8 bytes for `UNSEAL`). On
every other path the output descriptor is left untouched.

## Status and watch operations 26–27

The frozen contract is `docs/SEALED-DATASETS.md` section 3.

`STATUS` (operation 26) carries an empty payload and no descriptor. It needs
an activated, unexpired capability and no verb. It is not audited, and it
works while the vault is locked. A short, long, or trailing payload, or any
request descriptor, is `KSEC_ERR_PROTOCOL`. An expired, inactive, or
process-mismatched capability is `KSEC_ERR_DENIED` (the same code
`ksec_policy_authorize` returns for an expired capability; `KSEC_ERR_EXPIRED`
stays reserved for expired records). The success payload is a big-endian u32
version, which is 1 (`KSEC_STATUS_VERSION`), followed by a big-endian u32
flag word. Bit 0 (`KSEC_STATUS_INITIALIZED`, value 1) means a vault header is
loaded. Bit 1 (`KSEC_STATUS_RECOVERY_CONFIRMED`, value 2) means recovery has
been confirmed. Bit 2 (`KSEC_STATUS_UNLOCKED`, value 4) means the master key
is held. Every other bit is zero. The client rejects a version other than 1,
or a success payload that is not exactly these eight bytes, as
`KSEC_ERR_PROTOCOL`. A global lock clears every capability, so the caller
mints a new one before asking again.

`WATCH` (operation 27) carries an empty payload and no descriptor. It needs
the same live capability and an unlocked vault. A locked vault is
`KSEC_ERR_LOCKED`. The daemon returns one end of a fresh
`socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC)` and keeps the other.
Nothing is ever written on it. The client returns that end close-on-exec and
nonblocking. At most `KSEC_MAX_WATCHES` (128) watches exist; another request
is `KSEC_ERR_LIMIT`. The daemon closes its end, so the client observes
`POLLHUP`, on every path that closes identity leases for the whole vault:
global lock (idle timeout, logind session lock, SIGUSR1, `LOCK`), master
rotation, backup import, destructive reset, storage failure that forces
lock, and daemon stop. It also closes the watch on expiry of the capability
that asked and on disconnect of the connection that asked. Closing the
client end frees the slot on the daemon's next expire pass. Watches are not
per-record, so replacing or deleting a record does not close them.
Passphrase-slot rewrap, compaction, and backup export do not close them:
those paths preserve the unlocked vault and do not close every identity
lease.
