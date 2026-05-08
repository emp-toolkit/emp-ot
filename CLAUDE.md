# Project notes for AI coding agents

## Verifying wire-byte equivalence after a refactor

Run [test/trace_equiv.cpp](test/trace_equiv.cpp) under
`EMP_TEST_MODE=1` before and after the change, and diff the produced
trace files. Determinism comes from emp-tool's test-mode hook (see
[`emp-tool/docs/test_mode.md`](https://github.com/emp-toolkit/emp-tool/blob/main/docs/test_mode.md)),
which swaps every randomness source for a counter-derived stream.

```bash
EMP_TEST_MODE=1 ./run ./build/trace_equiv before
# … apply the refactor, rebuild …
EMP_TEST_MODE=1 ./run ./build/trace_equiv after

diff before.alice.send after.alice.send   # must be empty
diff before.alice.recv after.alice.recv   # must be empty
diff before.bob.send   after.bob.send     # must be empty
diff before.bob.recv   after.bob.recv     # must be empty
```

The default trace covers semi-honest IKNP RCOT at length 2^16 + 101.
For a different protocol or length, edit `trace_equiv.cpp` directly.

## Intentional wire-format changes

If a refactor changes the wire bytes on purpose, record the reason
and the commit hash here so the next person diffing traces against
an older baseline knows which deltas to expect.

- `9f7da81` — Half-Tree (cGGM) single-point COT (ePrint 2022/1431
  Fig 4). Per-tree level corrections went from 2·κ-bit pair-OT
  messages to 1·κ-bit cGGM corrections, halving the SPCOT wire bytes.
- `570726a` — `BaseCot` calls `iknp->rcot_send/rcot_recv` directly
  instead of the chosen-message `send_cot/recv_cot` wrapper. The
  chosen-message wrapper added a per-COT bit exchange so the receiver
  could specify exact choice bits; ferret never specifies them, so
  this was pure round-trip waste. Setup-phase wire bytes drop
  accordingly. Extend-phase wire is byte-identical content-wise but
  pre-COT data is now sourced from raw IKNP rcot rather than the
  corrected variant.
- SoftSpoken sfvole leaf-as-tweak switch — the SoftSpoken sub-VOLE
  PRG changed from `AES_{leaves[x]}(j)` (leaf-as-key) to
  `AES_K(j ⊕ leaves[x])` under a session-shared fixed AES key K
  (mirrors libOTe's MultiKeyAES and emp-tool's PRP / CCRH model).
  Output bytes change for every SoftSpoken-derived stream, including
  Ferret's bootstrap (which uses SoftSpoken<8>). IKNP traces are
  unaffected — IKNP doesn't touch SoftSpoken kernels.
- Ferret malicious mpcot consistency-check chi binding — the per-
  tree chi vector used in the F_{2^k} chi-fold was previously
  derived as `chi_i = expand(Hash(secret_sum_f2_i))`, binding only
  to the per-tree value. It now uses Fiat-Shamir over the full
  protocol transcript: FerretCOT::setup calls
  `io->enable_fs(party == ALICE)`, which has IOChannel maintain two
  per-direction SHA-256 transcripts that absorb every byte sent and
  received. mpcot.run() snapshots the FS digest *per tree* via
  `chi_seed_i = io->get_digest() = H(d_AB ‖ d_BA)` taken right
  after sending/receiving c[i], then PRG-expands chi[0..leave_n)
  from chi_seed_i (à la IKNP malicious). Each tree's chi binds the
  transcript through that tree, strictly stronger than a single
  round-final digest. Same on-wire byte counts, but the
  consistency-check digest content differs in malicious mode.
- Ferret mpcot drops `secret_sum_f2` from the wire — under cGGM the
  leveled correlation gives XOR(leaves) = Δ, and the per-tree
  punctured-correction value reduces to a constant
  `lsb_only_mask = makeBlock(0,1)` for every tree of every round.
  Both sides hardcode the constant; the per-tree 16-B field is no
  longer transmitted nor absorbed into the FS transcript. Steady-
  state RCOT wire drops from 0.27 to 0.25 bits/OT (~7%).
