# Synthetic fixture policy

Persistent vector and parser-corpus bytes are deterministic format examples,
not keys, credentials, account identifiers, private paths, or endpoints. Their
complete 1/1 vector-file and 26/26 corpus-file sets are digest-bound by the two
manifests in this directory.

Integration secrets and passphrases are generated afresh from the operating
system CSPRNG for each run, remain in pipes or process memory, are checked
absent from argv, environment, audit and persistent vault bytes, and are
overwritten before the test removes its caller-selected, validated scratch
directory. No
runtime-generated secret is retained as an artifact, so there is deliberately
no static secret allowlist.
