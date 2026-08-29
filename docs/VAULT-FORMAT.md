# Vault format v1

The implementation follows the A112-reviewed F112 format registry. All
integers are unsigned big-endian and all parsers reject unknown identifiers,
invalid lengths, trailing bytes, and out-of-grammar owner IDs before decryption
or state mutation.

Record associated data uses the `KSVAD001` domain and binds format version,
object type, KDF and AEAD IDs, vault UUID, object ID, revision, plaintext
length, and owner. Slot associated data uses the distinct `KSSAD001` domain and
binds the complete passphrase/recovery-slot KDF and wrap parameters.

Format v1 registries contain only Argon2id v1.3 (`pwhash_id=1`), libsodium
`crypto_kdf` (`kdf_id=1`), and independent per-object IETF
XChaCha20-Poly1305 (`aead_id=1`). ID zero and every unknown value are invalid.
Each object and key slot carries a fresh random 24-byte nonce.

Record plaintext begins with `KSRPL001`, version 1, a 16-bit flags field,
expiry, bounded type/label/field counts and the canonical field sequence. Flag
bit 0 means a nonzero grant section is present. That section contains a
big-endian 16-bit count followed by 1/16 through 16/16 grants, each encoded as
a big-endian 32-bit verb mask, big-endian 16-bit application-ID length, and
application-ID bytes. Grants must be strictly increasing by bytewise
application ID; duplicates, empty masks, `create`/`doctor`, unknown bits,
unknown flags, and trailing bytes fail closed. A record with 0/16 grants keeps
the original byte-exact encoding without the optional count.

The F113 device-identity schema is a stricter use of that unchanged record
format: owner `kilix-pairingd`, object/type `device-identity`, no expiry, 0/16
grants, and exactly one field named `private-key` containing 32 bytes. The
public X25519 identity is derived, not duplicated in storage. Its generation
anchor is BLAKE2b-256 over the exact 80 bytes
`KSECID01 || vault_uuid || record_id || be64(record_revision) || public_key`.
This anchor is a consumer consistency identifier, not a secret, MAC, rollback
counter, or substitute for record AEAD authentication.

Passphrase change leaves the random master key and recovery slot unchanged,
creates a fresh passphrase slot ID, salt, and nonce, increments the authenticated
header generation, and atomically replaces the header. An initialization whose
recovery rendering was lost may be retried only while recovery remains
unconfirmed and only after the existing passphrase slot authenticates; retry
replaces the recovery slot with fresh material and never activates the vault.

Master rotation creates a fresh random master key, rewraps both required slots,
re-encrypts every live record into a staged generation, reloads and compares the
staged records, and publishes the complete `vault.ksv`/`journal.ksj` pair with
one atomic directory exchange. The displaced encrypted pair is retained under
`.vault-previous-*`; it is not silently deleted.

Destructive reset is not rotation. It creates an independently random master,
vault UUID, slots, salts and nonces at generation 1 with recovery initially
unconfirmed. The staged empty header/journal pair is authenticated and reloaded
before one atomic directory exchange. The displaced directory is retained
byte-for-byte under `.vault-reset-retained-*` with no automatic deletion or
trust migration. Reset never copies labels, records, grants, peer state, or
identity metadata into the new UUID.

## Encrypted backup v1

The backup is independently authenticated and contains only the already
encrypted active header and journal inside a second authenticated envelope. Its
fixed 176-byte big-endian header is:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 8 | `KSVBAK01` |
| 8 | 2 | backup version 1 |
| 10 | 2 | Argon2id v1.3 ID |
| 12 | 2 | `crypto_kdf` ID |
| 14 | 2 | IETF XChaCha20-Poly1305 ID |
| 16 | 4 | Argon2id operations limit |
| 20 | 8 | Argon2id memory limit |
| 28 | 16 | fresh backup salt |
| 44 | 24 | fresh master-wrap nonce |
| 68 | 48 | wrapped 32-byte source master and tag |
| 116 | 16 | authenticated source vault UUID |
| 132 | 8 | authenticated source generation |
| 140 | 4 | encoded source-header length |
| 144 | 8 | encrypted-journal length |
| 152 | 24 | fresh payload nonce |

The wrap associated data is the exact 8-byte `KSBKSL01` domain, header bytes
8–43, header bytes 116–151, and a big-endian 32-bit wrapped-plaintext length.
The outer payload key is KDF context `KSBACK01`, subkey ID 1, derived from the
source master. The complete 176-byte header is payload associated data. Payload
plaintext is the exact encoded source header followed by the exact encrypted
journal; the file ends with its 16-byte payload tag.

Import rejects unknown IDs, out-of-range Argon2 parameters, inconsistent or
oversized lengths, wrong credentials, altered envelope bytes, an unauthenticated
inner header, and any invalid or torn inner journal before exchange. It writes
and syncs a separate directory, reloads the staged journal with the recovered
source master, then atomically exchanges directories and retains the displaced
directory. An unreadable active header is named as an unknown prior generation
and retained byte-for-byte so a valid backup can recover damaged storage.

`tests/vectors/full-v1.txt` freezes one complete synthetic passphrase slot,
recovery slot, authenticated header, serialized record, record associated data,
terminal keys, nonces, ciphertext, tag, derived X25519 public key, identity
anchor, and independently authenticated backup envelope. The generator is
reproduced during both normal and sanitizer test gates and its output must be
byte-identical.

The portable journal can identify a torn final record but never accepts an
authentication failure in a complete earlier record. A damaged file is retained
for explicit recovery. Whole-file offline rollback is not prevented.
