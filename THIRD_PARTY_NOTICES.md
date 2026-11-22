# Third-party notices

emp-ot vendors third-party source. Their licenses are retained in-tree
and installed alongside the library.

- **mlkem-native** (Post-Quantum Cryptography Alliance), an ML-KEM
  implementation derived from the pq-crystals Kyber reference code — used
  by the `BMM` post-quantum base OT (`third_party/mlkem-native/`, version
  and commit in its `VENDOR.md`). Licensed Apache-2.0 OR ISC OR MIT; a few
  files carry their own SPDX identifiers, as the upstream notice explains.
  The complete upstream notice is retained at
  `third_party/mlkem-native/LICENSE`.

emp-ot itself is licensed under Apache-2.0; see `LICENSE`.
