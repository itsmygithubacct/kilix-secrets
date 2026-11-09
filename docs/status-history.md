# Status history

The two paragraphs below were the README's status text on this branch
(`work/0.2.1-f112-kilix-secrets`), moved here verbatim. They describe the
repository before publication. Since then:

- The repository is public on GitHub.
- `main` is two commits ahead of this branch. `c7c5ebd` selects the measured
  H0 Argon2id production point (4 operations, 512 MiB, recorded in
  `docs/H0-CALIBRATION.txt` on `main`), and `da05600` records Review B
  acceptance and authorizes publication of `main`.
- Plebian-OS 0.2.3 pins `KILIX_SECRETS_REF`
  `da05600d9b52074281218b97da041a93fac22ece` on `main`.

On this branch the daemon still has no compiled-in production point, so the
second paragraph remains accurate for this branch's code.

---

This repository is an unqualified local implementation candidate for Plebian
OS / Kilix 0.2.1 F112. Design review A112 accepted the frozen design package;
independent implementation Review B and shared-repository integration remain
mandatory. No remote, push, tag, or publication is authorized.

The production service intentionally has no development KDF flags. A final
Argon2id point remains externally unselected until it is calibrated on the H0
4 GiB target; initialization without that selection fails closed.
