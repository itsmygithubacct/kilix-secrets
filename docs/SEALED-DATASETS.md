# Sealed datasets, status and watch (format and protocol amendment 1)

Status: frozen interface for implementation. Base commit `2c8c445`.
This document amends the A112-reviewed F112 design. It adds one record
object type, five protocol operations, one file format, CLI verbs and a
Python binding. Nothing in format v1, protocol v1 operations 1–22, or the
encrypted backup format changes meaning.

## 1. Purpose

A credential vault record holds at most 69,632 bytes and the whole vault at
most 1,024 records, shared by every application. An application whose data is
larger (a personal-finance book of several megabytes) cannot live inside the
vault. A *sealed dataset* keeps the data outside the vault, in a file the
application owns, encrypted under a key that never leaves the daemon.

- The vault stores one **dataset key** record per dataset family.
- The daemon **seals** plaintext into a sealed file and **unseals** it back.
  The application never sees the key.
- The application keeps the sealed file wherever it stores data, writes it
  atomically, and keeps previous generations itself.

Two small operations support long-running applications: **status** (is the
vault initialized, recovery-confirmed, unlocked) and **watch** (a descriptor
that hangs up when the vault locks).

## 2. Dataset key records (object type 4)

`KSEC_OBJECT_DATASET_KEY = 4`. Schema, all checked by
`ksec_validate_dataset_key_record`:

| Property | Value |
|---|---|
| object type | 4 |
| owner | the creating capability's application ID |
| type | exactly `dataset-key` (`KSEC_DATASET_KEY_TYPE`) |
| label | caller-chosen, ordinary label rules (1–128 bytes UTF-8, no controls) |
| expiry | 0 |
| fields | exactly one, named `dataset-key` (`KSEC_DATASET_KEY_FIELD`), 32 bytes |
| grants | none |

Rules:

1. Only `KSEC_OP_DATASET_CREATE` creates one. The daemon draws the 32 key
   bytes from `randombytes_buf` into secure memory. A client cannot supply
   key bytes.
2. PUT and REPLACE refuse object type 4 (`KSEC_ERR_INVALID`, already true of
   `parse_record_request`). PUT and REPLACE also refuse **any** record whose
   type string is `dataset-key`, whatever object type the client claims
   (`KSEC_ERR_INVALID`). REPLACE of an existing type-4 record is
   `KSEC_ERR_DENIED`: dataset keys are immutable.
3. GET of any field of a type-4 record is `KSEC_ERR_DENIED`, checked before
   authorization exactly as for device identities.
4. GRANT and REVOKE on a type-4 record are `KSEC_ERR_DENIED`.
5. DELETE works as for any record (owner, `delete` verb, two-ID confirmation).
   Deleting a dataset key makes every file sealed with it permanently
   unreadable. The CLI keeps its existing `--confirm` rule.
6. LIST and SHOW work; neither ever reveals the key.
7. Compaction, master rotation, encrypted backup export/import carry type-4
   records like any other record. Sealed files stay readable after rotation,
   compaction and a backup round trip into the same vault UUID.
8. Destructive reset removes every key; sealed files then fail with
   `KSEC_ERR_NOT_FOUND`.
9. Record associated data (`KSVAD001`) accepts object type 4. Object type 5
   and above stay invalid. The negative-corpus case `ad-object-type.case`
   moves from type 4 to type 5.

**Downgrade.** A daemon built before this amendment rejects object type 4 and
therefore refuses to load a vault that holds a dataset key. It fails closed:
nothing is deleted, and the amended daemon opens the vault again. This is an
accepted, documented consequence (owner decision 2026-11-13).

## 3. Protocol operations 23–27

All integers are big-endian. Every operation needs an activated capability
(the existing dispatch rule). `KSEC_OP_MAX` becomes 27. Payload grammar is
exact: a short, long or trailing payload is `KSEC_ERR_PROTOCOL` when the fixed
part is malformed and `KSEC_ERR_INVALID` when a field value is out of range,
matching the existing operations.

| ID | Name | Request payload | Request fd | Verb | Locked | Response payload | Response fd |
|---:|---|---|---|---|---|---|---|
| 23 | `DATASET_CREATE` | u16 label length, label | none | `create` | `LOCKED` | 16-byte record ID | none |
| 24 | `SEAL` | 16-byte record ID, u64 revision, u16 name length, name | sealed memfd: plaintext | `use` | `LOCKED` | none | sealed memfd: sealed file |
| 25 | `UNSEAL` | 16-byte record ID, u16 name length, name | sealed memfd: sealed file | `use` | `LOCKED` | u64 revision | sealed memfd: plaintext |
| 26 | `STATUS` | empty | none | none (live capability) | works | u32 version (1), u32 flags | none |
| 27 | `WATCH` | empty | none | none (live capability) | `LOCKED` | none | watch descriptor |

### 3.1 Request descriptors (SEAL, UNSEAL)

The daemon must never block on a client descriptor. The request descriptor
must be a memfd carrying at least `F_SEAL_WRITE | F_SEAL_GROW |
F_SEAL_SHRINK` (checked with `F_GET_SEALS`); anything else is
`KSEC_ERR_INVALID`. Its size comes from `fstat`; the daemon reads it with
`pread` from offset 0. Missing descriptor: `KSEC_ERR_PROTOCOL`.

- SEAL: plaintext size 0 … `KSEC_MAX_DATASET_BYTES` (64 MiB); larger is
  `KSEC_ERR_LIMIT`.
- UNSEAL: sealed size must be at most the sealed length of a 64 MiB
  plaintext with a 64-byte owner and 128-byte name; larger is
  `KSEC_ERR_LIMIT`.

### 3.2 Order of checks

DATASET_CREATE: payload grammar → unlocked → `authorize(create, own app)` →
record-count limit (`KSEC_ERR_LIMIT`) → audit `dataset-create begin` →
append → audit `ok`.

SEAL and UNSEAL: payload grammar → descriptor present → the connection has
no unread reply (`KSEC_ERR_BUSY`; review amendment 1, §10) → unlocked → record
exists and not deleted (`NOT_FOUND`) → `authorize_record_raw(use)` (`DENIED`)
→ record is a valid dataset key, else `KSEC_ERR_INVALID` → descriptor seals
and size → audit `seal`/`unseal begin` → work → audit `ok`.

UNSEAL then: parse the header prefix (`INVALID` on any grammar error) →
vault UUID, key record ID, owner and name must equal the vault's UUID, the
requested record ID, the record's owner and the requested name
(`KSEC_ERR_CONFLICT`) → file length must equal the exact sealed length
(`INVALID`) → decrypt every chunk into a fresh memfd (`KSEC_ERR_CRYPTO` on
any authentication failure, wrong tag sequence, or missing final tag) → seal
the memfd → reply with the revision and the descriptor. On any failure no
descriptor is returned.

Neither operation mutates the store. Neither touches a filesystem path.

### 3.3 STATUS flags

| Bit | Constant | Meaning |
|---:|---|---|
| 0 | `KSEC_STATUS_INITIALIZED` (1) | a vault header exists |
| 1 | `KSEC_STATUS_RECOVERY_CONFIRMED` (2) | recovery has been confirmed |
| 2 | `KSEC_STATUS_UNLOCKED` (4) | the master key is held |

Unknown bits are zero. STATUS needs no verb, only a live (activated,
unexpired) capability. It is not audited. It works while locked. Note that a
global lock clears every capability, so after a lock the caller mints a new
one before asking.

### 3.4 WATCH

The daemon returns one end of a fresh `socketpair(AF_UNIX, SOCK_SEQPACKET |
SOCK_CLOEXEC)` and keeps the other end. Nothing is ever written on it. The
daemon closes its end on: global lock (idle timeout, logind lock, SIGUSR1,
`LOCK`), master rotation, backup import, destructive reset, expiry of the
capability that asked, disconnect of the connection that asked, storage
failure that forces lock, and daemon stop. The client sees `POLLHUP` and asks
STATUS on a fresh capability to learn why. At most `KSEC_MAX_WATCHES` (128)
watches exist; more is `KSEC_ERR_LIMIT`. Watches reuse the identity-lease
lifecycle and must be closed on every path that closes identity leases.

## 4. Sealed dataset file v1

All integers big-endian. n = owner length, m = name length.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 8 | magic `KSDSET01` |
| 8 | 2 | format version, 1 |
| 10 | 2 | stream ID, 1 = libsodium `crypto_secretstream_xchacha20poly1305` |
| 12 | 4 | chunk size, exactly 65,536 |
| 16 | 16 | vault UUID |
| 32 | 16 | dataset key record ID |
| 48 | 8 | dataset revision (application-chosen) |
| 56 | 8 | plaintext length L, 0 … 67,108,864 |
| 64 | 2 | owner length n, 1 … 64 |
| 66 | n | owner application ID (app-ID grammar) |
| 66+n | 2 | name length m, 1 … 128 |
| 68+n | m | dataset name (label grammar) |
| 68+n+m | 24 | secretstream header |
| 92+n+m | … | chunks |

The **header prefix** is bytes `[0, 68+n+m)`.

- **Stream key**: `crypto_kdf_derive_from_key(32, subkey_id = 1, context =
  "KSDSET01", dataset_key)`. The record's key is never used directly.
- **Chunks**: k = max(1, ⌈L / 65,536⌉). Chunks 1 … k−1 carry exactly 65,536
  plaintext bytes; chunk k carries the rest (0 only when L = 0). Each chunk on
  disk is its plaintext length + 17 bytes. Chunks 1 … k−1 use
  `TAG_MESSAGE`; chunk k uses `TAG_FINAL`.
- **Associated data** of every chunk is the complete header prefix.
- **Exact length**: the file is exactly `92 + n + m + L + 17·k` bytes. Any
  other length, any unknown version, stream ID or chunk size, any length
  field out of range, an owner or name outside its grammar, a wrong tag on
  any chunk, a `TAG_FINAL` before chunk k or a missing one on chunk k is an
  error. Nothing follows the final chunk.
- Plaintext passes through secure (locked) buffers one chunk at a time.

The format adds nothing to rollback protection: an older sealed file of the
same dataset, sealed under the same key, still unseals and reports its
older revision. The application compares revisions itself.

## 5. Public C API (`include/kilix_secrets.h`)

```c
#define KSEC_DATASET_KEY_TYPE "dataset-key"
#define KSEC_DATASET_KEY_FIELD "dataset-key"
#define KSEC_DATASET_KEY_BYTES 32U
#define KSEC_MAX_DATASET_NAME 128U
#define KSEC_MAX_DATASET_BYTES (64U * 1024U * 1024U)
#define KSEC_STATUS_VERSION 1U
#define KSEC_STATUS_INITIALIZED 1U
#define KSEC_STATUS_RECOVERY_CONFIRMED 2U
#define KSEC_STATUS_UNLOCKED 4U

ksec_result ksec_dataset_create(ksec_client *client, const char *label,
                                uint8_t record_id[KSEC_RECORD_ID_BYTES]);
ksec_result ksec_seal_fd(ksec_client *client,
                         const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                         const char *dataset_name, uint64_t revision,
                         int input_fd, int output_fd);
ksec_result ksec_unseal_fd(ksec_client *client,
                           const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                           const char *dataset_name, int input_fd,
                           int output_fd, uint64_t *revision);
ksec_result ksec_status(ksec_client *client, uint32_t *flags);
ksec_result ksec_watch(ksec_client *client, int *watch_fd);
```

- `ksec_seal_fd` / `ksec_unseal_fd` read `input_fd` (any readable
  descriptor: file, pipe) to end of file into a client-made sealed memfd,
  bounded by the limits in §3.1 (`KSEC_ERR_LIMIT` beyond), send it, and write
  the reply descriptor's bytes sequentially to `output_fd` **only after the
  daemon has returned `KSEC_OK`**. On any failure the daemon reports, nothing
  is written to `output_fd`. If writing the reply to `output_fd` itself fails
  (`KSEC_ERR_IO`, for example `ENOSPC` or `EPIPE`), `output_fd` may hold a
  prefix of the output (review amendment 2, §10). A caller writes to a
  temporary file and renames.
- `ksec_status` returns the flags; a reply whose version is not 1 is
  `KSEC_ERR_PROTOCOL`.
- `ksec_watch` returns a close-on-exec, nonblocking descriptor.
- Additive ABI: the soname stays `libkilix-secrets.so.0`. `VERSION` becomes
  `0.2.0-dev`.

Internal API (`src/internal.h`, implemented in `src/dataset.c`):

```c
typedef struct {
    uint8_t vault_uuid[KSEC_UUID_BYTES];
    uint8_t key_record_id[KSEC_RECORD_ID_BYTES];
    uint64_t revision;
    uint64_t plaintext_length;
    char owner[KSEC_MAX_APP_ID + 1U];
    char name[KSEC_MAX_DATASET_NAME + 1U];
} ksec_dataset_header_info;

ksec_result ksec_dataset_encode_prefix(const ksec_dataset_header_info *info,
        uint8_t *output, size_t output_size, size_t *output_length);
ksec_result ksec_dataset_parse_prefix(const uint8_t *input, size_t input_length,
        ksec_dataset_header_info *info, size_t *prefix_length);
ksec_result ksec_dataset_sealed_length(uint64_t plaintext_length,
        size_t prefix_length, uint64_t *sealed_length);
ksec_result ksec_dataset_seal(const uint8_t key[KSEC_DATASET_KEY_BYTES],
        const ksec_dataset_header_info *info, int plaintext_fd, int output_fd);
ksec_result ksec_dataset_unseal(const uint8_t key[KSEC_DATASET_KEY_BYTES],
        const ksec_dataset_header_info *expected, int sealed_fd,
        int output_fd, ksec_dataset_header_info *actual);
ksec_result ksec_dataset_parse_create_request(const uint8_t *payload,
        size_t payload_length, char label[KSEC_MAX_LABEL + 1U]);
ksec_result ksec_dataset_parse_seal_request(const uint8_t *payload,
        size_t payload_length, uint8_t record_id[KSEC_RECORD_ID_BYTES],
        uint64_t *revision, char name[KSEC_MAX_DATASET_NAME + 1U]);
ksec_result ksec_dataset_parse_unseal_request(const uint8_t *payload,
        size_t payload_length, uint8_t record_id[KSEC_RECORD_ID_BYTES],
        char name[KSEC_MAX_DATASET_NAME + 1U]);
ksec_result ksec_validate_dataset_key_record(const ksec_owned_record *record);
```

- `ksec_dataset_parse_prefix` parses exactly one header prefix and requires
  `input_length >= prefix_length + 24`; it does not decrypt.
- `ksec_dataset_seal` reads exactly `info->plaintext_length` bytes from
  `plaintext_fd` with `pread` from offset 0 (fewer or more available is
  `KSEC_ERR_INVALID`) and writes the whole sealed file sequentially to
  `output_fd`.
- `ksec_dataset_unseal` reads `sealed_fd` with `pread` from offset 0 and its
  `fstat` size; `expected` supplies vault UUID, key record ID, owner and name
  to compare; `actual` receives the parsed header on success. Plaintext is
  written to `output_fd` as chunks authenticate; the caller discards
  `output_fd` on failure.

## 6. Command line additions (`kilix-secrets`)

| Verb | Behaviour |
|---|---|
| `dataset-create --label L` | prints the new 32-hex record ID |
| `seal RECORD --name N --revision R --input FILE\|- --output FILE\|-` | sealed output; FILE is created `O_EXCL`, mode 0600 |
| `unseal RECORD --name N --input FILE\|- --output FILE\|-` | plaintext output; FILE `O_EXCL` 0600; `-` refused when stdout is a terminal; prints `revision=R` on stderr |
| `replace RECORD --field NAME [--secret-fd N] [--raw]` | replaces the record's fields with that one field, keeping type, label and expiry |
| `get RECORD FIELD --output FILE\|--output-fd N` | guarded read: FILE `O_EXCL` 0600; a terminal is refused |
| `status` | prints `initialized=yes\|no recovery_confirmed=yes\|no unlocked=yes\|no`; works locked |
| `add … --raw` | keeps trailing CR/LF in the secret (default still strips them, as today) |

Exit codes stay those of the existing CLI; a locked vault keeps its existing
distinct code.

## 7. Python binding (`python/kilix_secrets`)

Standard library only (ctypes), Python 3.11+. It loads
`libkilix-secrets.so.0` from `KILIX_SECRETS_LIBRARY`, else the system search
path. It exposes every public C function, typed exceptions per
`ksec_result`, and three conveniences for long-running applications:

- `mint_for_child(pid, app_id, verbs, lifetime, record_id=None)`;
- `Session` — runs a short-lived worker child (`python -m
  kilix_secrets.worker`), mints a capability for it, proxies calls to it,
  and replaces it transparently when its capability expires;
- `Watcher` — keeps a WATCH open through a worker, renews it before the
  capability lifetime ends, and calls back on lock.

`seal_file` / `unseal_file` write to a temporary file beside the target,
fsync, rename and fsync the directory. Installed by `make install` under
`$(PREFIX)/lib/python3/dist-packages/kilix_secrets`.

## 8. Line endings

`read_sensitive_fd` strips trailing CR/LF from every sensitive input, including
encoded records and backup frames, so a record whose last field ends in a
line ending fails to parse. Stripping becomes opt-in per call site: kept for
passphrases and recovery secrets (human-typed), removed for encoded records
and framed binary inputs.

## 9. What this amendment does not change

Format v1 record encoding, slots, header, journal and backup v1 bytes; the
existing vectors; operations 1–22; capability rules; the 1,024-record and
128 MiB journal limits; the threat model's same-UID boundary.

## 10. Amendments after independent review (2026-11-13)

Made by the supervisor after review seat B (`reviews/REVIEW-B.md`, findings
B-3 and B-5). Neither changes the file format, the vectors or operations
1–22.

1. **Unread replies (B-3).** Each SEAL and UNSEAL reply is a memfd of up to
   about 64 MiB that stays in the socket queue until the client reads it. A
   client that pipelines requests without reading could make the daemon pin
   one such memfd per request. The daemon now refuses SEAL and UNSEAL with
   `KSEC_ERR_BUSY` while the requesting connection has an unread reply
   (`ioctl(SIOCOUTQ)` greater than zero), checked right after the descriptor is
   found present. Unread dataset replies are therefore bounded at one per
   connection, 64 in total.
2. **Partial output (B-5).** The client cannot take back bytes already written
   to a pipe or a full disk, so a write failure after `KSEC_OK` may leave a
   prefix in `output_fd`. The call still returns `KSEC_ERR_IO`.
