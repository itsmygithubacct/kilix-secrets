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

## Dataset key records (object type 4)

The frozen contract is `docs/SEALED-DATASETS.md` section 2.

Object type 4 is a dataset key. Record associated data (`KSVAD001`) accepts
object types 1, 2, 3 and 4. Object type 5 and every greater value stay invalid;
`tests/corpus/ad-object-type.case` carries type 5. The plaintext uses the
unchanged record encoding: expiry 0, no grants, type `dataset-key`, a label
under the ordinary label rules, and exactly one field named `dataset-key`
whose value is 32 bytes. The daemon draws those bytes. PUT and REPLACE cannot
store object type 4 or the type string `dataset-key`. GET, GRANT and REVOKE
refuse the record. DELETE, LIST, SHOW, compaction, master rotation and
encrypted backup carry it like any other record, so a file sealed under the
key stays readable after those operations in the same vault UUID. A daemon
built before this amendment rejects object type 4 and refuses to load a vault
that holds one. Nothing is deleted.

## Sealed dataset file v1

The frozen contract is `docs/SEALED-DATASETS.md` section 4.

Integers are big-endian. `n` is the owner length and `m` is the name length.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 8 | `KSDSET01` |
| 8 | 2 | version 1 |
| 10 | 2 | stream ID 1 (`crypto_secretstream_xchacha20poly1305`) |
| 12 | 4 | chunk size 65536 |
| 16 | 16 | vault UUID |
| 32 | 16 | dataset key record ID |
| 48 | 8 | dataset revision |
| 56 | 8 | plaintext length L, 0 through 67108864 |
| 64 | 2 | owner length n, 1 through 64 |
| 66 | n | owner application ID |
| 66+n | 2 | name length m, 1 through 128 |
| 68+n | m | dataset name |
| 68+n+m | 24 | secretstream header |
| 92+n+m | | chunks |

The header prefix is bytes `[0, 68+n+m)`. The stream key is
`crypto_kdf_derive_from_key` with subkey 1 and context `KSDSET01`, taken from
the 32-byte dataset key. The record key is never the stream key. Chunk count
is `k = max(1, ceil(L / 65536))`. Chunks 1 through k−1 each carry 65536
plaintext bytes and `TAG_MESSAGE`. Chunk k carries the remainder, which is 0
only when L is 0, and `TAG_FINAL`. Each chunk on disk is its plaintext length
plus 17 bytes. The associated data of every chunk is the complete header
prefix. The file is exactly `92 + n + m + L + 17·k` bytes. Any other length,
unknown version, stream ID or chunk size, length field out of range, owner or
name outside its grammar, wrong tag, early `TAG_FINAL`, or missing final tag
is an error.

Plaintext passes through locked memory one chunk at a time. Unseal compares
the vault UUID, key record ID, owner and name with the caller's expected
values before decryption.

`tests/vectors/dataset-v1.txt` freezes one dataset key, the derived stream
key, the header prefix and the complete sealed file for plaintext lengths 0,
100 and 65537, together with each plaintext SHA-256. The generator installs a
deterministic `randombytes` implementation only while it runs: a fixed 32-byte
seed, advanced between draws, backed by `randombytes_buf_deterministic`.
`make test` and `make sanitize` regenerate the file and require byte-identical
output.
