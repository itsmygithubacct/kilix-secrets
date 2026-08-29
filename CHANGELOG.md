# Changelog

## Unreleased

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
