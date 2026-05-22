# Wire-trace hashes for tracking protocol communication changes

You're about to change a protocol — refactoring, swapping in a new
gadget, retuning a parameter, anything that touches code on the path
between `send_data` / `recv_data`. This doc tells you how to detect
whether that change altered the bytes that actually cross the wire.

The test is [`test/trace_hash.cpp`](../test/trace_hash.cpp). It runs
every OT / sVOLE protocol in the repo (base OTs, OT extensions, both
sVOLE flavors, in semi and malicious modes) and prints one SHA-256
digest per direction per protocol — derived from the IOChannel
Fiat-Shamir transcript over a fresh `NetIO` per protocol.

If your refactor doesn't change any wire bytes, the digests stay
exactly the same. If they change, the protocol's wire format
changed.

## Quick workflow

```bash
# Build (release; debug uses smaller stress lengths)
cmake --build build -j

# Snapshot before the change
EMP_TEST_MODE=1 ./run ./build/trace_hash | grep '^[A-Za-z(]' > /tmp/before.txt

# Apply your refactor, rebuild

EMP_TEST_MODE=1 ./run ./build/trace_hash | grep '^[A-Za-z(]' > /tmp/after.txt

diff /tmp/before.txt /tmp/after.txt
```

`EMP_TEST_MODE=1` swaps every randomness source for a counter-derived
stream (see [`emp-tool/docs/test_mode.md`](https://github.com/emp-toolkit/emp-tool/blob/main/docs/test_mode.md));
without it, the hashes are non-deterministic and the diff is useless.

Empty diff → wire-byte equivalent. Any change → see below.

## Reading a non-empty diff

Each line of the output is one protocol invocation:

```
CO                   send=b0ac916e9e5aefdc recv=1527f501eb006b21
                       ↑ first 16 hex chars of SHA-256 over each direction
```

The hashes are taken from ALICE's perspective. ALICE's
`send` digest = BOB's `recv` digest (they observe the same wire
bytes from opposite ends), so a single party's view is enough.

A non-empty diff means at least one of the listed protocols sends
different bytes than before. The shape of the diff tells you the
blast radius:

| Diff pattern | What it means |
|---|---|
| One row changes | That protocol's wire format moved. |
| All `Ferret(...)` + `F2kVOLE` + `FpVOLE` change | You probably touched something inside Ferret or its inner gadget — the sVOLE protocols use Ferret internally for base COTs. |
| `*VOLE` rows change but `Ferret` doesn't | You touched the sVOLE-specific layer (mpsvole / chi-fold / bootstrap). |
| All RCOT-mali rows change but semi don't | Malicious-mode check (chi-fold) changed. |
| Base-OT rows change | You touched a base OT (or an EC group helper they share). |
| `SoftSpoken<2>` changes but `SoftSpoken<8>` doesn't | `k`-specific code path. |

## You changed the hash. Now what?

A hash change is not automatically bad. There are three categories:

1. **Unintended.** Your refactor was supposed to be wire-byte-neutral
   — better factoring, naming, performance, etc. The hash must not
   change. Track down what's different and either fix the refactor
   or revert. Common culprits:
   - Reordered field accumulation (e.g. swapping the order of two XORs
     in a chi-fold loop — algebraically equivalent but produces
     different intermediate hash bytes if the hash inputs change order).
   - Changed PRG-derivation order (e.g. sampling Δ before vs after a
     base-OT call).
   - Changed buffer alignment or chunk size where the protocol observes
     it on the wire.

2. **Intentional.** You're changing the protocol on purpose — adding
   a new round, removing a redundant byte, switching a hash function,
   etc. The hash should change. **Update the canonical hash table in
   the README** so the next refactor's baseline is the new value.
   In the commit message:
   - State which protocols are affected.
   - State what the wire-byte change is.
   - State whether peers running the old code can still talk to peers
     running the new code (usually no — wire-format changes break
     compatibility).

3. **Suspicious.** You don't immediately recognize why the hash
   changed. **Stop.** Either bisect to find the responsible commit /
   line, or expand the test (drop into the byte-level
   [`test/trace_equiv.cpp`](../test/trace_equiv.cpp), which dumps
   every wire byte to disk for a single protocol so you can `diff`
   the raw bytes and find the offset of the divergence). Don't
   commit until you understand what changed.

## What the test does NOT catch

- **Memory-only refactors.** If you change how leaves are stored on
  the local side but not how they're sent, hashes stay the same.
- **Non-deterministic protocol behavior.** With `EMP_TEST_MODE=0`,
  every run differs — the test mode is the only thing that makes
  hashes reproducible.
- **Per-OS / per-arch differences.** PRG seeding under `EMP_TEST_MODE`
  is platform-independent (counter-derived), but if a protocol picks
  up entropy from elsewhere (e.g. OpenSSL nondeterministic ECDH
  blinding when not pinned), hashes will differ between machines.
  Pin the baseline by running on the same host that produced it.
- **Receiver-side abort paths.** A hash captures bytes that crossed
  the wire successfully. If a malicious check fires and the receiver
  errors out, the hash captures everything up to the abort point.

## Extending the test

If you add a new protocol or want to test a new parameter combination:

1. Add a `measure(party, port, "<name>", <send_first>, [&](NetIO* io){
   run_*(io, party, length, ...); });` line in `trace_hash.cpp`.
2. Pick `send_first` to match what the protocol's internal `enable_fs`
   would have used — the protocol's `if (!io->fs_enabled())
   enable_fs(<convention>)` should be a no-op when our pre-enable
   matches. (RCOT extensions: `is_ot_sender() == (party == ALICE)`.
   sVOLE: `is_delta_holder()`.)
3. Run, capture the new line, paste it into the README.

The baseline hash table in the README is the source of truth — if
you add a protocol, the README must show its hash.
