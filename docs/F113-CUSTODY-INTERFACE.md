# F113 custody consumer interface candidate

Status: implementation candidate, owner freeze 0/1, independent Review B 0/1.
This document specifies only the F112-to-F113 custody boundary. It clears 0/1
F113, 0/1 KP1, 0/1 Noise, 0/1 acoustic, and 0/1 multiplexer claim.

## Record and authority

The one local device-identity record has these exact invariants:

- owner `kilix-pairingd`;
- object/type `device-identity`;
- no expiry;
- exactly 0/16 grants; and
- exactly one field named `private-key`, containing the raw 32-byte X25519
  private key.

Creation, replacement and confirmed deletion use record-scoped launcher or
service-supervisor capabilities. Production key use requires a live `use`
capability scoped to this exact record, process, supervisor, connection and
expiry. Generic get, grant and revoke operations refuse this object class.

## The 5/5 F113-facing dispositions

1. **Private-key use/retrieval.** `ksec_identity_open` atomically consumes one
   fixed descriptor frame, validates it, and copies the raw 32-byte private key
   into an exact caller-owned buffer. `kilix-pairingd` must lock that buffer
   before the call and clear/unlock it on every exit. This is plaintext delivery
   to pairingd; it is neither a sealed key descriptor nor an opaque DH/signing
   operation handle. The returned descriptor is empty after delivery and is
   retained only as an invalidation lease. The multiplexer receives exactly
   0/1 private keys and 0/1 F112 lease descriptors.

2. **Public-key access.** `ksec_identity_info_get` derives the X25519 public key
   inside the vault daemon and returns only versioned public metadata through a
   sealed descriptor. It returns 0/1 private keys and 0/128 leases. The private
   open call returns the identical public metadata atomically with key delivery.
   Pairingd may cache the non-secret public result. The multiplexer obtains an
   authorized public identity or opaque pairing result through F113 IPC; it does
   not call F112 directly.

3. **Locked-state failure.** Every explicit, authenticated-session, signal,
   idle, monitor-failure or shutdown lock closes all identity leases. New
   private and public calls return `KSEC_ERR_LOCKED`. Pairing and paired-mode
   operations are unavailable, pairingd clears its private buffer, and there is
   no production plaintext file, second encrypted slot, cached-private-key, or
   manual-mode fallback.

4. **Rotation/backup generation binding.** The version-1 anchor is
   BLAKE2b-256 over exactly
   `KSECID01 || vault_uuid || record_id || be64(record_revision) || public_key`.
   Passphrase-slot rewrap and master-key re-encryption preserve all anchor
   inputs. Master rotation nevertheless closes every lease and requires a fresh
   capability/open. Local identity-key rotation is an explicit record replace:
   it advances the revision, changes the public key and anchor, and closes the
   matching lease. Backup export changes nothing. Import always closes every
   lease and locks the vault; an exact restored identity reopens under the same
   anchor, while an expected-anchor mismatch returns `KSEC_ERR_CONFLICT` and
   creates 0/1 leases. Reset creates a new vault UUID with 0/1 old identity
   records and forces revocation/re-pairing.

5. **Deletion/revocation.** Deletion requires the exact record ID twice, creates
   no replacement, closes every matching lease, and makes later access return
   `KSEC_ERR_NOT_FOUND`. Device identities cannot have cross-application F112
   grants, so grant revocation is not an identity-rotation mechanism.
   Capability expiry, target/supervisor death and connection loss close the
   lease. Remote-peer revocation and tombstones belong to F113; deleting or
   rotating the local key requires F113 to revoke/re-pair peers rather than
   migrating trust from a label, address or old record.

## Pollable close contract

At most 128/128 identity leases exist. The descriptor is close-on-exec and
nonblocking. After `ksec_identity_open` returns, the initial 144/144 bytes have
already been consumed; later `POLLHUP`, `POLLERR`, or EOF is an irrevocable
invalidation. Pairingd must then stop new and live identity-dependent work,
wipe the private buffer, close the descriptor, and discard opaque operations.
The descriptor carries no reason code. A fresh authorized query distinguishes
`LOCKED`, `NOT_FOUND`, `CONFLICT`, or a still-matching generation.

The daemon closes the relevant lease on 10/10 local classes:

1. explicit/session/signal/idle global lock;
2. authenticated session-monitor failure;
3. matching-record replace;
4. matching-record delete;
5. master-key rotation;
6. backup import;
7. destructive reset;
8. capability expiry or target/supervisor death;
9. client connection loss; and
10. daemon stop/failure or a storage failure that forces global lock.

Passphrase rewrap, compaction and backup export preserve the live lease. A
generation mismatch supplied at open time is synchronous
`KSEC_ERR_CONFLICT`, with 0/1 lease created. A later local mismatch caused by
replace/import/reset first closes the pollable lease; reopening with the stale
expected anchor then returns conflict or not-found. An F113 peer-store
generation conflict is not observable by F112: F113 must close its own opaque
operations and downstream live leases when its comparison fails.

## Required consumer sequence

1. During explicit first provisioning/recovery only, query the current public
   info without an expected anchor and durably bind the returned anchor to the
   selected local identity. Normal operation supplies that expected anchor.
2. Allocate and lock exactly 32 bytes, then call `ksec_identity_open` with the
   expected anchor. Treat every non-OK result as pairing unavailable.
3. Keep both the `ksec_client` connection and returned lease open. Poll the
   lease before advancing an identity-dependent state machine and after any
   asynchronous wait. The atomically returned info must equal the selected
   public identity/anchor.
4. On close/error, prevent further application release, invalidate opaque
   operations and live leases, clear the private buffer, and require a fresh
   authorized open. Never pass the private buffer or F112 descriptor to the
   multiplexer.

The lease cannot revoke plaintext already copied into a compromised or
non-cooperating pairing daemon. The portable anchor also cannot detect a
coherent rollback that restores both the vault and F113's expected-anchor/peer
state to the same older version. Those are explicit limits, not cleared claims.
