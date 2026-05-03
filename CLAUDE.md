# Project notes for AI coding agents

## Wire-trace baseline

The current baseline reflects two intentional wire changes since
the original ferret protocol:

- Commit `9f7da81` — Half-Tree (cGGM) single-point COT (ePrint
  2022/1431 Fig 4). Per-tree level corrections went from 2·κ-bit
  pair-OT messages to 1·κ-bit cGGM corrections, halving the SPCOT
  wire bytes.
- **Reorg R6** — `BaseCot` calls `iknp->rcot_send/rcot_recv`
  directly instead of the chosen-message `send_cot/recv_cot`
  wrapper. The chosen-message wrapper added a per-COT bit
  exchange so the receiver could specify exact choice bits;
  ferret never specifies them, so this is pure round-trip waste.
  Setup-phase wire bytes drop accordingly. Extend-phase wire is
  byte-identical (same trace file size, but content differs
  because `pre_cot_data` is now sourced from raw IKNP rcot
  rather than the corrected variant).

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
