# Changelog

## Unreleased

- Add sealed datasets (`docs/SEALED-DATASETS.md`). A dataset key is a new
  record object type 4: 32 bytes the daemon generates, never returns and
  never replaces. Operations 23 `DATASET_CREATE`, 24 `SEAL` and 25 `UNSEAL`
  encrypt and decrypt an application's own file of up to 64 MiB under that
  key, through sealed memfds. The file format `KSDSET01` is libsodium
  secretstream with the whole header prefix as associated data on every
  64 KiB chunk, an exact length, and deterministic vectors in
  `tests/vectors/dataset-v1.txt`. A daemon older than this change refuses
  to unlock a vault that holds a dataset key; it fails closed and leaves the
  data directory unchanged.
- Add operation 26 `STATUS` (initialized, recovery confirmed, unlocked; no
  verb, not audited, works while locked) and operation 27 `WATCH`, a
  descriptor the daemon hangs up on lock, rotation, import, reset,
  capability expiry, disconnect, storage failure and stop (at most 128).
- Read PUT and REPLACE record bodies byte-exact. The daemon used to strip a
  trailing CR or LF from them, which cut an encoded record whose last value
  ended in one and refused it as invalid input. Passphrases and recovery
  secrets still have trailing CR and LF bytes stripped.
- Add CLI verbs `dataset-create`, `seal`, `unseal`, `replace`, `get` and
  `status`. Output files are new 0600 files and are never overwritten; a
  failed operation removes the file it created. `get` and `unseal --output -`
  refuse a terminal. `add` and `replace` still strip trailing CR and LF bytes
  from the value unless given `--raw`.
- Add the standard-library Python binding `kilix_secrets` with a `Session`
  worker process and a `Watcher` (`docs/PYTHON.md`), installed and packaged
  with the library. `VERSION` is 0.2.0-dev; the soname is unchanged.
- Extend the parser harness, negative corpus and limits tests to the new
  operations and the sealed file format.
- Establish the local-only F112 implementation candidate after accepted A112.
- Add deterministic crash-boundary injection, full cryptographic vectors,
  recovery-rendering retry, and atomic passphrase-slot rotation.
- Add transactional master-key rotation and independently authenticated,
  encrypted-only backup export/import with atomic restore and damaged-history
  retention.
- Add canonical bounded record grants, metadata-only inspection, Kitty
  clipboard delivery with compare-before-clear, and authenticated logind
  session locking.
- Require exact destructive-delete confirmation and add crash-safe destructive
  reset with a new vault identity and retained displaced encrypted generation.
- Add an isolated authenticated session-event harness, staged package lifecycle
  tests, dependency/SBOM evidence, and third-party notices.
- Add the exclusive F113 identity schema, atomic raw-key/public-anchor delivery,
  stale-generation refusal, and 128/128 bounded pollable invalidation leases.
- Bound mutation streaming to one 4,096-byte frame, add 65,536/65,536-case
  fuzz closure, and prove the 64/64 connection, one-thread and RSS ceilings.
- Accept root-owned parent directories that report the kernel overflow uid
  when the daemon runs in a user namespace with no mapping for root, as a
  sandboxed systemd user service does. Such a parent must not be writable by
  group or others; the sticky world-writable exception still needs a real
  uid 0. Outside such a namespace the rule is unchanged.
