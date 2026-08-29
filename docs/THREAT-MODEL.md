# Threat model

## Protected cases

The locked vault is designed to protect secret values and encrypted metadata
from offline inspection of the data directory, backups, or copied vault files.
The daemon rejects a different UID, unsafe filesystem objects, malformed or
oversized protocol messages, unauthenticated records, revision discontinuity,
and unknown format or algorithm identifiers. It avoids secret values in argv,
the environment, ordinary socket replies, logs, paths, and temporary files.

## Honest limits

The design does not protect an unlocked secret from root, a compromised kernel,
code injected into the daemon or intended consumer, or malware already running
with the user's full session authority. A hostile same-UID process can trace a
cooperating process or alter user-owned startup state. Capability policy is a
cooperative boundary that prevents accidental cross-application use; it is not
a sandbox.

Memory locking and explicit clearing reduce exposure but do not make memory
forensics impossible. Clipboard managers, terminal scrollback, screenshots,
and consuming-application behavior are outside the vault's control. Replacing
the complete portable vault with an older valid copy while the daemon is
stopped may be undetectable; no trusted rollback counter is claimed.

There is no recovery backdoor. Losing every valid key slot loses the data.
