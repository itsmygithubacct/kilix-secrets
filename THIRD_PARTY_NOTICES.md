# Third-party notices

`kilix-secrets` is MIT-licensed as recorded in `LICENSE`. It dynamically links
system packages and vendors 0/1 third-party source trees.

- libsodium `1.0.18-1+deb13u1` is primarily ISC-licensed and includes
  separately identified permissive/public-domain components. The complete
  Debian machine-readable notice is installed by `libsodium23` at
  `/usr/share/doc/libsodium23/copyright`; its candidate SHA-256 is
  `10d3576a7a0af8afb5601f358c06eb8c24b02192bb71ed4fb9a328a0979ec74b`.
- libsystemd `257.13-1~deb13u1` is covered by the systemd package's
  machine-readable notice, whose principal library licence is LGPL-2.1+ and
  which identifies component-specific licences. The complete notice is at
  `/usr/share/doc/libsystemd0/copyright`; its candidate SHA-256 is
  `a79e4b379cabbd960bb44f6cc1a069081a3778c59a25ee529b68df5a2cb7d27d`.
- glibc and libcap are transitive system runtime dependencies. Their complete
  Debian notices remain in `/usr/share/doc/libc6/copyright` and
  `/usr/share/doc/libcap2/copyright`, with candidate SHA-256s
  `f5788886720a2605a946e81d571e6c8162b09f58d2e2ceb8d36e5768fccd850d` and
  `04f9fb974e10f6ca0cd226811f72b3855f8383daad0e5de7adac8d5b0b7796c3`.

Packagers must ship the applicable distribution copyright files with the
corresponding packages. These pointers and hashes aid verification; they do not
replace the full licence texts or Debian package obligations.
