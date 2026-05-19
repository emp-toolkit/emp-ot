# Streaming API

Every OT-extension and sVOLE-extension instance is a streaming
producer: callers either ask for a fixed-size batch at a time
(`begin` → `next* → `end`) or hand off the chunking to the library
(`run(data, num)`). This doc covers the lifecycle, the leftover
buffer, the dual-role wrapper, auto-rollover, and the Fiat-Shamir
hooks.

The base lives in
[`emp-ot/common/streaming_extension.h`](../emp-ot/common/streaming_extension.h)
as `StreamingExtension<Element>`.

## The contract

Four pure virtuals each subclass implements:

```cpp
virtual int64_t chunk_size() const = 0;
virtual void    begin() = 0;
virtual void    next(Element* out) = 0;
virtual void    end() = 0;
```

Plus one public non-virtual entry point the base provides:

```cpp
void run(Element* data, int64_t num);   // one-shot (leftover-buffer drain)
```

The lifecycle is

```
   begin()  ─► next() ─► next() ─► ... ─► next() ─► end()
                                                       │
                                                       ▼
                                                   (session
                                                    closed;
                                                    can begin
                                                    again)
```

`chunk_size()` is the unit each `next()` emits — one cGGM tree's
leaves for Ferret, one batch for IKNP/SoftSpoken, one tree's
LPN-folded outputs for Svole. Constant per instance after setup.

**Session tripwire**: a single bool on the base. Subclass overrides
call protected helpers from inside `begin/next/end`:

- `enter_session_()` at the top of `begin()` — asserts no prior session
  was left open, then flips the flag.
- `assert_in_session_()` inside `next()` — catches `next()` called
  outside a begin/end pair.
- `exit_session_()` at the bottom of `end()` — clears the flag.

Each helper is one line and the subclass is free to do its real work
around them. The pattern replaces the NVI wrapper that used to live
on the base (`begin/next/end` non-virtual public + `do_begin/do_next/
do_end` protected virtuals) — a single set of virtuals is now both
the public API and the override point, and the tripwire is opt-in via
the helpers rather than enforced by the base.

## Lazy setup

`StreamingExtension` doesn't run any setup in its constructor — the
ctor just stores `party / malicious / setup_done = false`. The first
`begin()` call is responsible for performing the protocol's bootstrap
and flipping `setup_done = true`. Every later begin sees
`setup_done == true` and skips the bootstrap.

This lets outer protocols configure the instance (e.g.
`set_delta` / `set_choice_seed`) between construction and the
first session — both setters assert `!setup_done` to catch use after
bootstrap has consumed Δ / choice randomness.

## The leftover buffer (`run(data, num)`)

```cpp
void run(Element *data, int64_t num) {
    const int64_t chunk = chunk_size();
    int64_t produced = drain_leftover(data, num);
    if (produced == num) return;

    begin();
    while (produced + chunk <= num) {
        next(data + produced);
        produced += chunk;
    }
    if (produced < num) {
        // Tail handling: write one more chunk into a per-instance
        // scratch, copy out the prefix the user asked for, save
        // the suffix for the next call.
        if ((int64_t)leftover_.size() < chunk) leftover_.resize(chunk);
        next(leftover_.data());
        int64_t take = num - produced;
        std::memcpy(data + produced, leftover_.data(),
                    take * sizeof(Element));
        leftover_pos_   = take;
        leftover_count_ = chunk - take;
    }
    end();
}
```

The point: callers can request arbitrary `num`, not necessarily a
multiple of `chunk_size()`. The base class buffers the suffix
internally, so the *next* call to `run()` first drains that suffix
and then either returns or continues with `begin`/`next` loop.

In other words, repeated `run(...)` calls on the same instance with
`num != k·chunk_size()` don't pay a fresh chunk per call.

## The polymorphic entry on OTExtension

`StreamingExtension` is single-role: each instance, given its
`party`, runs one side of the protocol. `OTExtension` inherits the
streaming lifecycle (`begin/next/end/run/chunk_size`) verbatim and
additionally implements `RandomCOT::rcot` — the polymorphic one-shot
entry that callers holding a `RandomCOT*` (chosen-correlation
auto-wrapper inside `COT::send_cot/recv_cot`, generic-OT consumers in
emp-zk / emp-sh2pc) use without knowing the instance's party:

```cpp
//   begin/next/end / run / chunk_size  (StreamingExtension contract — inherited)
//   rcot(data, num)                    (RandomCOT abstract; final on OTExtension)
```

`OTExtension::rcot` is a one-line wrapper over the inherited `run()`
— same leftover-buffer service, just exposed under the
polymorphic-RandomCOT name. Streaming-savvy callers use
`begin/next/end` (or `run` for one-shot) directly; the role is
implicit in `party` and no party-assertion is needed.

The dispatch tree inside `OTExtension`:

```
  rcot ─► run(data, num)  ─► begin / loop next / end (leftover-buffer drain)

  begin ─┐
  next   ├─► subclass override (no NVI hook layer)
  end    │
         │ Concrete subclasses (IKNP, SoftSpoken, Ferret) override
         │ begin / next / end directly:
         │   - IKNP / SoftSpoken: inline party-test → private
         │     send_{begin,next,end}_ / recv_{begin,next,end}_ helpers.
         │   - Ferret: one unified body per stage (party-dispatch
         │     happens inside the per-tree private helpers).
```

## Auto-rollover inside do_next

`StreamingExtension::next` does no rollover — it just asserts the
session is active and calls `do_next(out)`. The protocol-specific
auto-rollover (calling end+begin transparently when the round's
user-visible budget is full) lives inside the subclass's `next`:

```cpp
// Ferret::next (simplified)
void Ferret::next(block* out) {
    assert_in_session_();
    const int64_t user_budget_trees = param.t - param.refill_trees;
    if (tree_idx_ == user_budget_trees) {
        end();   // exit_session_ flips the tripwire
        begin(); // enter_session_ flips it back
    }
    process_one_tree_(reinterpret_cast<AuthValueFerret*>(out));
}
```

```cpp
// Svole::next (simplified)
void Svole::next(AuthValue* out) {
    assert_in_session_();
    const int64_t user_budget_trees = param.t - param.refill_trees;
    if (tree_idx_ == user_budget_trees) { end(); begin(); }
    process_one_tree_(out);
}
```

Because `end → exit_session_` flips the tripwire false and the
following `begin → enter_session_` flips it back true, the rollover
sequence passes the protected helpers cleanly while still landing in
a valid session for the caller's next() that follows.

IKNP and SoftSpoken don't need rollover — they have no notion of
"refill the next round's seed material from this round's tail",
so each `next()` is just one chunk and `end()` is explicit.

## Fiat-Shamir hooks

`IOChannel` (in emp-tool) carries two optional SHA-256 transcripts —
`fs_send_` and `fs_recv_` — that absorb every byte sent / received
once `enable_fs(send_first)` is called. Both must be called by
exactly one party with `send_first=true` (the other passes false).

Streaming extensions use FS in two ways:

1. **Per-protocol chi seeds.** Inside a malicious-mode `do_next` /
   `do_end`, the gadget snapshots `io->get_digest()` to derive
   chi vectors. The digest is computed deterministically from the
   wire bytes both parties have observed, so both parties get the
   same chi vector without an extra round of communication.

2. **Diagnostic per-direction digests.** `io->get_send_digest()`
   and `io->get_recv_digest()` return the running SHA-256 of each
   direction's transcript. The `trace_hash` test uses these to
   verify wire-byte equivalence across refactors. See
   [`wire-trace-hashes.md`](wire-trace-hashes.md).

Subclasses that need FS for chi seeds enable it lazily — e.g.
Ferret's `bootstrap_()` does `if (!io->fs_enabled()) io->enable_fs(is_ot_sender());`.
A protocol may also have FS pre-enabled by an outer harness; the
`if (!fs_enabled())` guard makes that a no-op.

## Destruction in-session

```cpp
~StreamingExtension() {
    if (in_session_) error("...");
}
```

A protocol object destructed in the middle of a session is a bug —
the leftover buffer may hold un-consumed bytes; the peer is waiting
for more. The base catches this at all build flavors (not just debug).

## What about `setup_done`?

`setup_done` is a public-on-the-base bool. Subclasses set it true
inside their lazy bootstrap. Setters that must fire pre-bootstrap
(`set_delta`, `set_choice_seed`) assert `!setup_done`. The base does
not check `setup_done` itself — it's a contract between the subclass
and the caller, surfaced through the asserts.

## See also

- [`class-organization.md`](class-organization.md) — who inherits
  from whom; where each carrier and gadget lives.
- [`wire-trace-hashes.md`](wire-trace-hashes.md) — using the FS
  digests to verify refactors don't change wire bytes.
