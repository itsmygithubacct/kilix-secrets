# kilix-secrets

`kilix-secrets` is the local credential-vault provider for Kilix. It consists
of a per-user daemon, a C11 client library, and an administrative CLI. Secret
values are encrypted in an authenticated append-only journal and are delivered
to authorized consumers through descriptors, not command arguments or
environment variables.

This repository is an unqualified local implementation candidate for Plebian
OS / Kilix 0.2.1 F112. Design review A112 accepted the frozen design package;
independent implementation Review B and shared-repository integration remain
mandatory. No remote, push, tag, or publication is authorized.

## Build

The build requires the Debian 13 `libsodium-dev` package matching runtime
`libsodium23` 1.0.18-1+deb13u1.

```sh
make
make test
make sanitize
```

Packagers may override `SODIUM_CPPFLAGS` and `SODIUM_LDLIBS` when building
against an unpacked, independently verified sysroot.

## Security boundary

The daemon protects a locked vault against offline inspection and refuses
malformed storage, protocol, and policy state. Application capabilities reduce
accidental cross-application disclosure among cooperating same-UID programs.
They do not contain root, a compromised kernel, injected daemon code, or a
hostile process that already controls the user's session. Portable whole-file
rollback while the daemon is stopped can be undetectable.

See `docs/THREAT-MODEL.md`, `docs/VAULT-FORMAT.md`, and `SECURITY.md` before
using or reviewing the code.
