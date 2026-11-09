# kilix-secrets

`kilix-secrets` is the local credential-vault provider for Kilix. It consists
of a per-user daemon, a C11 client library, and an administrative CLI. Secret
values are encrypted in an authenticated append-only journal and are delivered
to authorized consumers through descriptors, not command arguments or
environment variables.

Ships in Plebian-OS 0.2.3: provisioning builds the pinned commit into
`/usr/local` and enables the per-user socket for every user. This README
describes `work/0.2.1-f112-kilix-secrets`, the GitHub default branch. The
pinned commit is on `main`, two commits ahead; see
[Branches and status](#branches-and-status).

## What it does

- Keeps one encrypted vault per user under `~/.local/share/kilix-secrets`,
  served by `kilix-secretsd` on `$XDG_RUNTIME_DIR/kilix-secrets/control.sock`
  (a `SOCK_SEQPACKET` socket that systemd activates on first use).
- Derives the vault key with Argon2id from a passphrase, and also creates a
  recovery secret that is shown once at `init`.
- Stores typed records with named fields, each object encrypted with
  XChaCha20-Poly1305 and bound to its owner, revision and vault.
- Hands a secret to a program through a descriptor (`run`, `ksec_get_to_fd`) or to
  the clipboard with clear-after (`copy`), never through argv or a reply.
- Limits each application to the records and verbs it was granted
  (`read`, `use`, `replace`, `delete`, `list-own`).
- Makes encrypted-only backups, rotates the passphrase or the master key, and
  resets the vault only after a literal confirmation.
- Holds the device identity for pairing and hands it only to its owner,
  `kilix-pairingd`, through a dedicated custody call.

## Quick start

Build and test from a checkout (Debian 13 with `libsodium-dev` and
`libsystemd-dev`):

```sh
make
make test
sudo make install PREFIX=/usr/local
systemctl --user enable --now kilix-secrets.socket
```

Use the vault through the CLI. Passphrases and secret values are read from the
terminal, or from a descriptor given with `--secret-fd`:

```sh
kilix-secrets init                 # new passphrase; prints the recovery secret once
kilix-secrets unlock --recovery    # confirm the recorded recovery secret
kilix-secrets add --type api-token --label example --field token
kilix-secrets list
kilix-secrets run RECORD token -- some-command   # KILIX_SECRET_FD names the descriptor
kilix-secrets lock
```

On this branch `init` fails closed unless the daemon was started with the
paired development flags `--development-kdf-ops` and
`--development-kdf-mem-mib`; the installed unit does not pass them.

## Usage

`kilix-secrets [--socket PATH] [--app APP] COMMAND [ARGS]`

| Command | What it does |
|---|---|
| `init [--secret-fd N] [--recovery-fd N]` | Create the vault and its recovery secret |
| `unlock [--recovery] [--secret-fd N]` / `lock` | Open or close the vault |
| `passwd [--secret-fd N]` | Change the passphrase slot |
| `add --type TYPE --label LABEL --field NAME [--secret-fd N]` | Store a new record |
| `list` / `show RECORD` | List own records / show one record's metadata |
| `grant RECORD APP --verbs read,use[,replace,delete,list-own]` / `revoke RECORD APP` | Grant or revoke another application's access |
| `copy RECORD FIELD [--clear-seconds N]` | Put a field on the clipboard and clear it later |
| `run RECORD FIELD -- COMMAND [ARG ...]` | Run a command with the field on a descriptor |
| `delete RECORD --confirm RECORD` | Delete a record |
| `rotate [--passphrase-fd N] [--recovery-fd N]` | Re-encrypt under a new master key |
| `export --output FILE` / `import --input FILE` | Encrypted backup and restore |
| `reset --confirm RESET-VAULT-AND-LOSE-IDENTITY` | Replace the vault with a new identity |
| `compact` / `doctor` | Compact the journal / report vault and daemon state |

`kilix-secretsd [--systemd | --socket PATH] --data-dir PATH [--idle-seconds N]`
runs the daemon. Programs link `libkilix-secrets` (`pkg-config kilix-secrets`)
and use the calls in [`include/kilix_secrets.h`](include/kilix_secrets.h),
such as `ksec_connect`, `ksec_put`, `ksec_get_to_fd` and `ksec_grant_record`.

## How it works

```
CLI / program --ksec_connect--> control.sock (SOCK_SEQPACKET, 0600)
                                     |
                       kilix-secretsd (per user, socket-activated)
                       capability check -> grant check -> journal
                                     |
        ~/.local/share/kilix-secrets: append-only encrypted journal
        secret out: sealed descriptor / memfd / clipboard, never argv
```

The CLI is a supervisor: it forks a worker and asks the daemon for a
capability bound to that worker process, one application ID (`kilix-secrets`
unless `--app` names another) and the verbs the command needs. Every request is a framed
packet from protocol v1; unknown operations, flags, lengths and identifiers
fail closed ([docs/PROTOCOL.md](docs/PROTOCOL.md)). The vault is a journal of
independently encrypted objects whose associated data binds format, algorithm
IDs, vault UUID, object ID, revision and owner
([docs/VAULT-FORMAT.md](docs/VAULT-FORMAT.md)). The daemon follows the user's
login sessions over the system bus and locks the vault when a session locks or
ends, and after 15 idle minutes (`--idle-seconds`). Building,
packaging and the destructive-operation rules are in
[docs/build-and-package.md](docs/build-and-package.md); the device-identity
custody call is in [docs/custody-abi.md](docs/custody-abi.md).

## Security boundary

The daemon protects a locked vault against offline inspection and refuses
malformed storage, protocol, and policy state. Application capabilities reduce
accidental cross-application disclosure among cooperating same-UID programs.
They do not contain root, a compromised kernel, injected daemon code, or a
hostile process that already controls the user's session. Portable whole-file
rollback while the daemon is stopped can be undetectable.

See `docs/THREAT-MODEL.md`, `docs/VAULT-FORMAT.md`,
`docs/F113-CUSTODY-INTERFACE.md`, and `SECURITY.md` before using or reviewing
the code.

## Branches and status

The GitHub default branch is `work/0.2.1-f112-kilix-secrets`. On it the daemon
has no compiled-in production KDF point and `doctor` reports
`kdf_point=unselected`. `main` adds the measured production point (Argon2id,
4 operations, 512 MiB) and the Review B acceptance record, and is the commit
Plebian-OS 0.2.3 pins (`KILIX_SECRETS_REF` `da05600d`). The README's earlier
status text is kept in [docs/status-history.md](docs/status-history.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/build-and-package.md](docs/build-and-package.md) | Build requirements, make targets, Debian package, CLI command rules |
| [docs/custody-abi.md](docs/custody-abi.md) | The F113 device-identity custody calls and stable anchor |
| [docs/F113-CUSTODY-INTERFACE.md](docs/F113-CUSTODY-INTERFACE.md) | Full F112-to-F113 custody consumer contract |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | Local protocol v1: packets, operations, descriptors |
| [docs/VAULT-FORMAT.md](docs/VAULT-FORMAT.md) | Vault format v1: records, slots, associated data |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Protected and unprotected cases |
| [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) | Dependency and SBOM record |
| [docs/IMPLEMENTATION-BASELINE.md](docs/IMPLEMENTATION-BASELINE.md) | Design inputs the implementation is bound to, by digest |
| [docs/status-history.md](docs/status-history.md) | The README's earlier status text and what changed since |
| [SECURITY.md](SECURITY.md) | Security policy |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | Third-party licences |
| [CHANGELOG.md](CHANGELOG.md) | Changes |

## Related repositories

- [plebian-os](https://github.com/itsmygithubacct/plebian-os#readme): pins,
  builds and installs this repository during provisioning.
- [kilix](https://github.com/itsmygithubacct/kilix#readme): the terminal
  desktop this vault is built for.

## Part of Plebian-OS

kilix-secrets is one of the repositories behind
[Plebian-OS](https://github.com/itsmygithubacct/plebian-os#readme), a Debian
install whose desktop is [Kilix](https://github.com/itsmygithubacct/kilix#readme)
running the [Kilix 95](https://github.com/itsmygithubacct/kilix-95#readme)
desktop through [Pleb](https://github.com/itsmygithubacct/pleb#readme).
Plebian-OS provisioning fetches the pinned commit, builds it and installs the
daemon, CLI, library and user socket under `/usr/local`. The map of every
repository and how it ships is on the
[components page](https://github.com/itsmygithubacct/plebian-os/blob/main/docs/components.md).

## License

MIT. See [LICENSE](LICENSE).
