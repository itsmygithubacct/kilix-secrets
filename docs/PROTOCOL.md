# Local protocol v1

The daemon uses a per-user `SOCK_SEQPACKET` Unix socket. Every packet begins
with a fixed header containing the protocol version, operation, flags, request
identifier, and bounded payload length. Truncation, trailing bytes, unknown
operations, and unknown flags are refused.

The frozen v1 operation registry covers capability activation/minting, vault
initialization, unlock/lock, create/replace/read/delete/list, doctor,
compaction, and passphrase-slot change. Passphrase change uses the same
dedicated-descriptor rule as initialization and unlock; its general packet
contains only a zero selector.

Capabilities, passphrases, recovery material, records, metadata listings, and
secret replies travel on dedicated descriptors. General socket packets carry
only bounded routing metadata. All descriptors are close-on-exec unless a
supervisor deliberately passes one capability descriptor to its exact child.
