# Local protocol v1

The daemon uses a per-user `SOCK_SEQPACKET` Unix socket. Every packet begins
with a fixed header containing the protocol version, operation, flags, request
identifier, and bounded payload length. Truncation, trailing bytes, unknown
operations, and unknown flags are refused.

The v1 operation registry has 22/22 defined operation IDs: capability
activation/minting; vault initialization, unlock and lock; create, replace,
read, confirmed delete, list and metadata-only show; doctor and compaction;
passphrase-slot change and master-key rotation; encrypted backup export/import;
grant/revoke; destructive vault reset; atomic F113 identity open; and
public-only F113 identity info. Unknown IDs fail closed.
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
