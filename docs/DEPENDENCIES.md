# Dependency and SBOM record

This record describes the local F112 Review-B candidate built on Debian 13
amd64. No third-party source is vendored into this repository.

## Direct production dependencies

| Component | Debian binary / source version | Use | Exact local evidence |
| --- | --- | --- | --- |
| libsodium | `libsodium23` / `libsodium` `1.0.18-1+deb13u1` amd64 | Argon2id, BLAKE2b KDF, XChaCha20-Poly1305, randomness, constant-time comparison, locked allocation and clearing | `/usr/lib/x86_64-linux-gnu/libsodium.so.23.3.0` SHA-256 `85e2e494494f4f50c4b6d2b4ae90e885da1bfdefd52c4cc5767fd10abff62505`; Debian copyright SHA-256 `10d3576a7a0af8afb5601f358c06eb8c24b02192bb71ed4fb9a328a0979ec74b` |
| libsystemd | `libsystemd0`, `libsystemd-dev` / `systemd` `257.13-1~deb13u1` amd64 | authenticated system-bus subscription and current-user graphical-session inventory | `/usr/lib/x86_64-linux-gnu/libsystemd.so.0.40.0` SHA-256 `c59f9015342de9c2dcb2decccb3d83218849fe3e4388c723a6528254fd7606f0`; `sd-bus.h` SHA-256 `17ecf87426e811161ddc225b7bc87a31886efa1ae3645d5939f976ae8d32f890`; `sd-login.h` SHA-256 `e80b94f3e0d794d74d165fbd0d6b3553001b32d31d6e9bc5027c74aa6127dd88`; Debian copyright SHA-256 `a79e4b379cabbd960bb44f6cc1a069081a3778c59a25ee529b68df5a2cb7d27d` |
| C runtime | `libc6` / `glibc` `2.41-12+deb13u3` amd64 | C/POSIX/Linux runtime | `/usr/lib/x86_64-linux-gnu/libc.so.6` SHA-256 `fa430b8f298f817a266046af84a77533185ad6fc4406c7d3787b5a0a0c207826` |

The candidate is pinned to the Debian snapshot
`https://snapshot.debian.org/archive/debian/20260727T000000Z`. The independently
frozen crypto-source, binary, patch and API evidence remains in the F112 release
record `0.2.1-F112-LIBSODIUM-EVIDENCE.md`; this repository does not duplicate or
silently amend that authority.

`readelf -d` shows that `libkilix-secrets.so.0` directly needs only
`libsodium.so.23` and `libc.so.6`. The daemon additionally directly needs
`libsystemd.so.0`. On this image, `libsystemd.so.0` adds `libcap.so.2` and
`libm.so.6`; Debian packages `libcap2` / source `libcap2`
`1:2.75-10+deb13u1+b1` / `1:2.75-10+deb13u1` and `libc6` supply those transitive
objects. The exact local `libcap.so.2.75` SHA-256 is
`41217b0af128444f66dee8adda52b2ceaf19da00e5b0b155e2b87b857671286b`.

## Build and test dependencies

The build requires a C11 compiler, `make`, `ar`, `pkg-config`, matching
`libsodium-dev` headers (or the independently verified header sysroot), and
`libsystemd-dev`. Tests additionally require Python 3, `readelf`,
`systemd-analyze`, and `dbus-daemon` (`dbus` source/binary version `1.16.2-2` on
the recorded host). The private D-Bus instance is test-only; production connects
only to the authenticated system bus.

## Reproduction checks

`make test` performs warning-clean builds, verifies direct ELF dependencies,
compiles one staged C consumer, checks the systemd units in a staged root, and
runs install/uninstall/reinstall manifest comparisons. A final Plebian OS image
must independently reproduce package versions, hashes, dependency resolution,
licence installation, service behavior and offline operation during Review B;
this development-host record does not itself qualify the shared OS image.
