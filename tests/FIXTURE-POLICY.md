# Synthetic fixture policy

Persistent vector and parser-corpus bytes are deterministic format examples,
not credentials, account identifiers, private paths, or endpoints. The full
cryptographic vector deliberately includes unmistakably synthetic fixture keys
and secrets so exact slot-wrap and record-AEAD bytes can be reproduced; none is
generated from or accepted for production data. The complete 2/2 vector-file
and 26/26 corpus-file sets are digest-bound by the two manifests in this
directory.

Integration secrets and passphrases are generated afresh from the operating
system CSPRNG for each run, remain in pipes or process memory, are checked
absent from argv, environment, audit and persistent vault bytes, and are
overwritten before the test removes its caller-selected, validated scratch
directory. No runtime-generated secret is retained as an artifact. The static
synthetic vector set is allowlisted only through its exact 2/2 manifest hashes.
