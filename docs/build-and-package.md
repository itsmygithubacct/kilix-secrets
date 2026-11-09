# Build, package and administer

This section was moved verbatim from the README. The command list and the
destructive-operation rules below describe `tools/kilix-secrets.c` on this
branch.

## Build

The build requires the Debian 13 `libsodium-dev` package matching runtime
`libsodium23` 1.0.18-1+deb13u1 and `libsystemd-dev` matching runtime
`libsystemd0` 257.13-1~deb13u1. See `docs/DEPENDENCIES.md` and
`THIRD_PARTY_NOTICES.md` for the exact local SBOM and licence evidence.

```sh
make
make test
make sanitize
make deb TEST_TMPDIR=/path/to/private-scratch
make deb-test TEST_TMPDIR=/path/to/private-scratch
```

Packagers may override `SODIUM_CPPFLAGS` and `SODIUM_LDLIBS` when building
against an unpacked, independently verified sysroot.
`make deb` produces a reproducible, source-bound Debian package in `dist/` and
refuses a dirty source tree. `make deb-test` additionally exercises dpkg
install, upgrade, rollback, remove, reinstall, and purge in an isolated root;
package removal and purge preserve user vault data.

The administrative CLI includes `init`, `unlock`, `lock`, `passwd`, `add`,
`show`, `grant`, `revoke`, `copy`, `run`, `list`, `delete`, `rotate`, `export`,
`import`, `compact`, and `doctor`. Destructive record deletion requires the
exact form `delete RECORD --confirm RECORD`.
Backup output is encrypted-only, is created as a new 0600 file, and is never
silently overwritten. Import verifies the complete artifact, retains the
displaced generation, then locks the vault. Restoring an older valid artifact
is an explicit rollback; the portable backend has no trusted rollback counter.
Destructive vault reset requires the literal confirmation
`RESET-VAULT-AND-LOSE-IDENTITY`, creates a new vault UUID, retains the displaced
encrypted directory without automatic expiry, and requires recovery proof
before the new identity can unlock. Every peer must then be revoked or re-paired.
