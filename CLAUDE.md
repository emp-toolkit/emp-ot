# Project notes for AI coding agents

## Wire-trace baseline (post-cGGM migration)

Commit `9f7da81` ("Migrate ferret SPCOT to Half-Tree (cGGM); drop
OTPre from data path") incorporated the Half-Tree single-point COT
optimization (Guo-Yang-Wang-Zhang-Xie-Liu-Zhao, ePrint 2022/1431,
Fig 4). This was a **deliberate wire-format change**: per-tree
level corrections went from 2·κ-bit pair-OT messages to 1·κ-bit
cGGM corrections, halving the SPCOT communication. The pre-cGGM
byte trace is no longer valid; **the new baseline is checked in
under `test/baseline/`**.

Files:
- `test/baseline/ferret-cggm.{alice,bob}.snap` — post-setup state
  for both parties (random; serves as deterministic input for the
  replay phase).
- `test/baseline/ferret-cggm.{alice,bob}.trace` — wire bytes
  produced by the deterministic replay over the snap.

### Verifying byte-trace stability after a refactor

`test_ferret_trace` writes outputs alongside the snap, so do not
overwrite the baseline. Use a /tmp prefix for the run:

```bash
cp test/baseline/ferret-cggm.{alice,bob}.snap /tmp/
./run ./build/test/test_ferret_trace /tmp/ferret-cggm trace
diff /tmp/ferret-cggm.alice.trace test/baseline/ferret-cggm.alice.trace
diff /tmp/ferret-cggm.bob.trace   test/baseline/ferret-cggm.bob.trace
```

Both diffs must be empty for a byte-trace-preserving refactor.

### When the wire format intentionally changes

Regenerate both snap and trace, replace the baseline files, and
note the reason (with the commit hash that introduced the change)
in this file's history section above.
