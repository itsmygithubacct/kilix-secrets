# F112 implementation baseline

Implementation began only after the independent A112 report returned ACCEPT.
The baseline is immutable by digest:

| Input | SHA-256 |
| --- | --- |
| A112 report | `70ad72d578aa4ccdd81f87cc8d45b4b3360ae80052297c4b2927a3034e2eafb2` |
| A112 manifest | `b956b2005ad98d41e146906cf0e4180f2537ed41eba5e4f6a2e6ef4b9c166f87` |
| Approved decisions | `48253fb4536c2ca40c6d975afeaef37f8c9989d3dd43c867e243c3e3c5ab38c4` |
| Format-v1 registry | `e0b80bf82b2aa7b7c245b5a27a863c1074465807fe5223ea3ea2855c4b23be6f` |
| Synthetic AD vectors | `4ae49dbb2e9350246e4e05d3a80c6cccba7173715e4fd4047064221a046f1fa9` |

The accepted construction is independent per-object
`crypto_aead_xchacha20poly1305_ietf` with a fresh 24-byte CSPRNG nonce.
Secretstream is excluded from format v1.
