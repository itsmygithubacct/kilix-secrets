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

The portable journal can identify a torn final record but never accepts an
authentication failure in a complete earlier record. A damaged file is retained
for explicit recovery. Whole-file offline rollback is not prevented.
