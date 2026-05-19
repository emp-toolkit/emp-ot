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

Three pure virtuals each subclass implements:

```cpp
virtual int64_t chunk_size() const = 0;
virtual void    do_begin() = 0;
virtual void    do_next(Element* out) = 0;
virtual void    do_end() = 0;
```

Plus four public entry points the base provides:

```cpp
void begin();
void next(Element* out);   // writes exactly chunk_size() Elements
void end();
void run(Element* data, int64_t num);   // one-shot
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

Calling `next()` outside a begin/end pair asserts. Calling `begin()`
inside one also asserts (the session tripwire is a single bool).

`chunk_size()` is the unit each `next()` emits — one cGGM tree's
leaves for Ferret, one batch for IKNP/SoftSpoken, one tree's
LPN-folded outputs for Svole. Constant per instance after setup.

## Lazy setup

`StreamingExtension` doesn't run any setup in its constructor — the
ctor just stores `party / malicious / setup_done = false`. The first
`do_begin()` call is responsible for performing the protocol's
bootstrap and flipping `setup_done = true`. Every later begin sees
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

## chunk_size, chunk_ots, chunk_extends

Three names for the same thing — historical, kept as aliases:

- `chunk_size()` is the canonical pure virtual on `StreamingExtension`.
- `chunk_ots()` is a non-virtual alias on `OTExtension`, OT-domain idiom.
- `chunk_extends()` is a non-virtual alias on `Svole`, sVOLE-domain idiom.

All return the same value. New code should prefer the domain alias
local to the class.

## The dual-role wrapper on OTExtension

`StreamingExtension` is single-role: each instance, given its
`party`, runs one side of the protocol. `OTExtension` is single-role
internally too, but it inherits `RandomCOT`'s dual-role API
(`send_rcot` / `recv_rcot`) and exposes the single-role lifecycle
under both an OT-domain name and a role-agnostic name:

```cpp
//   begin/next/end   (StreamingExtension contract — inherited)
//   rcot_begin/next/end  (OT-domain alias for begin/next/end)
//   send_rcot(data, num) / recv_rcot(data, num)
//       (RandomCOT one-shot pair; asserts party then delegates to run())
```

`send_rcot` / `recv_rcot` are party-asserting wrappers around
`run()`. They exist so a caller that holds a polymorphic `RandomCOT*`
can call the right method without knowing the instance's party.
Internal call sites that already know the role (Ferret nesting,
Svole pull_cots_) use them too.

`rcot_begin/next/end` is the recommended path for streaming-savvy
callers: it skips the role assertion entirely (the role is implicit
in `party`).

The dispatch tree inside `OTExtension`:

```
  send_rcot ─┐
             ├─► assert(is_ot_sender()) ─► run(data, num)
  recv_rcot ─┘

  rcot_begin ─► begin() ─┐
  rcot_next  ─► next()   ├─► do_begin / do_next / do_end
  rcot_end   ─► end()    │       │
                         │       │ (OTExtension's default
                         │       │  implementation)
                         │       ▼
                         │   if (is_ot_sender())
                         │       do_send_rcot_{begin,next,end}();
                         │   else
                         │       do_recv_rcot_{begin,next,end}();
                         │
                         │ Subclasses override either:
                         │   - the per-role hooks (IKNP, SoftSpoken), or
                         │   - do_begin/do_next/do_end directly (Ferret).
```

## Auto-rollover inside do_next

`StreamingExtension::next` does no rollover — it just asserts the
session is active and calls `do_next(out)`. The protocol-specific
auto-rollover (calling end+begin transparently when the round's
user-visible budget is full) lives inside the subclass's `do_next`:

```cpp
// Ferret::do_next (simplified)
void Ferret::do_next(block* out) {
    const int64_t user_budget_trees = param.t - param.refill_trees;
    if (tree_idx_ == user_budget_trees) {
        do_end();
        do_begin();
    }
    process_one_tree_(reinterpret_cast<AuthValueFerret*>(out));
}
```

```cpp
// Svole::do_next (simplified)
void Svole::do_next(AuthValue* out) {
    const int64_t user_budget_trees = param.t - param.refill_trees;
    if (tree_idx_ == user_budget_trees) {
        do_end();
        do_begin();
    }
    process_one_tree_(out);
}
```

The wrapper `next()` sees a single contiguous session even though,
under the hood, several end+begin pairs may have fired. Callers
don't observe the round boundary.

IKNP and SoftSpoken don't need this — they have no notion of
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

## Session tripwire and destruction

```cpp
~StreamingExtension() {
    assert(!in_session_ && "missing end()");
}
```

A protocol object destructed in the middle of a session is a bug —
the leftover buffer may hold un-consumed bytes; the peer is waiting
for more. The assert catches this in debug builds.

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
