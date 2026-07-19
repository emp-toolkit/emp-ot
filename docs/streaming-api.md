# Streaming API

Every OT-extension and sVOLE-extension instance is a streaming
producer. Callers pick one of three access styles:

- a fixed-size batch at a time, owning the session (`begin` → `next*`
  → `end`);
- an arbitrary-size *incremental* draw within a session they own
  (`begin` → `next_n*` → `end`) — refills a chunk internally;
- hand the whole thing to the library as a one-shot (`run(data, num)`),
  which opens and closes a session per call.

This doc covers the lifecycle, the leftover buffer, `next_n`, the
dual-role wrapper, auto-rollover, and the Fiat-Shamir hooks.

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

Plus two public non-virtual entry points the base provides:

```cpp
void run   (Element* data, int64_t num);  // one-shot: opens+closes a session per call
void next_n(Element* dst,  int64_t n);    // buffered draw within a caller-owned session
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

- `enter_session_()` at the top of `begin()` — uses the always-on
  `emp::expecting` contract to reject a prior session left open, then
  flips the flag.
- `expect_in_session_()` inside `next()` and at the top of `end()` — an
  always-on check before the override produces a chunk or performs any
  protocol I/O.
- `exit_session_()` at the bottom of `end()` — repeats the always-on
  active-session check, then clears the flag.

Each helper is one line and the subclass is free to do its real work
around them. A single set of virtuals (`begin`/`next`/`end`) is both
the public API and the override point, and the tripwire is opt-in via
the helpers rather than enforced by the base.

Public boundary operations use `emp::expecting`, so their contracts
remain active in release builds: double `begin`, `end` without `begin`,
`run` during an open session, and `next_n` without an open session are
all rejected. A direct out-of-session call to virtual `next()` is also
rejected in release builds.

## Lazy setup

`StreamingExtension` doesn't run any setup in its constructor — the
ctor just stores `party / malicious / setup_done = false`. The first
`begin()` call is responsible for performing the protocol's bootstrap
and flipping `setup_done = true`. Every later begin sees
`setup_done == true` and skips the bootstrap.

This lets outer protocols configure the instance (e.g.
`set_delta` / `set_choice_seed`) between construction and the
first session. Preconditions on these configuration APIs use
`emp::expecting`, so misuse is rejected in release builds too:

- OT-extension `set_delta` is sender-only, requires a non-null bit
  buffer with bit 0 set, and must run before bootstrap.
- `set_choice_seed` is receiver-only and must run before bootstrap.
- OT-extension and sVOLE `set_sid` must run before bootstrap.
- sVOLE `set_delta` is Δ-holder-only and pre-bootstrap; reading
  `delta()` is Δ-holder-only. The F2k carrier additionally requires
  Δ's least-significant bit to be one. Fp instead requires a canonical
  nonzero field element and samples one automatically when not overridden.

## The leftover buffer (`run(data, num)`)

```cpp
void run(Element *data, int64_t num) {
    expecting(!in_session_,
              "StreamingExtension::run: active streaming session");
    expecting(num >= 0, "StreamingExtension::run: negative element count");
    expecting(num <= max_element_count_(),
              "StreamingExtension::run: element byte count overflow");
    expecting(num == 0 || data != nullptr,
              "StreamingExtension::run: null output for nonzero count");
    if (num == 0) return;

    const int64_t chunk = chunk_size();
    validate_chunk_size_(chunk);             // positive; byte count fits
    int64_t produced = drain_leftover(data, num);
    if (produced == num) return;

    begin();
    while (chunk <= num - produced) {        // subtraction avoids overflow
        next(data + produced);
        produced += chunk;
    }
    if (produced < num) {
        // Tail handling: write one more chunk into a per-instance
        // scratch, copy out the prefix the user asked for, save
        // the suffix for the next call.
        if (leftover_.size() < static_cast<size_t>(chunk))
            leftover_.resize(static_cast<size_t>(chunk));
        next(leftover_.data());
        int64_t take = num - produced;
        std::memcpy(data + produced, leftover_.data(),
                    static_cast<size_t>(take) * sizeof(Element));
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

The boundary checks happen before touching the leftover buffer or
starting protocol work. With no session active, a zero count is a true
no-op: `data` may be null, no leftover is consumed, and `chunk_size` /
`begin` / `next` / `end` are not called. Negative counts, a null output
for a nonzero count, counts whose `num * sizeof(Element)` cannot fit in
`int64_t`, and nonpositive or byte-overflowing chunk sizes are rejected
in every build flavor. `run` rejects being called during a
caller-owned streaming session even when `num == 0`.

## Incremental draw (`next_n(dst, n)`)

`run()` is convenient but opens and closes a session *per call*. For a
backend that consumes the stream a little at a time (emp-zk draws one
COT per AND gate, a few per multiplication), that means paying the
per-round end-work — `run_refill_`'s refill trees **plus** the
malicious chi-fold check — every `chunk_size()` elements, amortized
over a single produced tree instead of a whole round (~hundreds of
trees). That was a ~20× slowdown in emp-zk before this API.

`next_n` instead draws from one long-lived session the caller owns. It
fills whole chunks *straight into* `dst` (no intermediate copy) and only
buffers a sub-chunk remainder, so the per-call copy is bounded by one
chunk regardless of `n` — same structure as `run()`, minus begin/end:

```cpp
void next_n(Element *dst, int64_t n) {
    expecting(n >= 0,
              "StreamingExtension::next_n: negative element count");
    expecting(n <= max_element_count_(),
              "StreamingExtension::next_n: element byte count overflow");
    expecting(n == 0 || dst != nullptr,
              "StreamingExtension::next_n: null output for nonzero count");
    expecting(in_session_, "StreamingExtension::next_n: call begin first");
    if (n == 0) return;

    const int64_t chunk = chunk_size();
    validate_chunk_size_(chunk);
    int64_t got = drain_leftover(dst, n);      // 1. prior partial tail (stream order)
    while (chunk <= n - got) {                 // 2. whole chunks: no copy
        next(dst + got);
        got += chunk;
    }
    if (got < n) {                             // 3. sub-chunk remainder via leftover_
        if (leftover_.size() < static_cast<size_t>(chunk))
            leftover_.resize(static_cast<size_t>(chunk));
        next(leftover_.data());
        int64_t take = n - got;
        std::memcpy(dst + got, leftover_.data(),
                    static_cast<size_t>(take) * sizeof(Element));
        leftover_pos_ = take; leftover_count_ = chunk - take;
    }
}
```

`next_n` applies the same signed-count, byte-overflow, null-buffer,
and chunk-size checks as `run`. It additionally requires an active
caller-owned session even when `n == 0`; once that requirement is met,
a zero count is a no-op and `dst` may be null. Each concrete `next()`
also applies the always-on session expectation when producing a chunk.

Writing whole chunks directly into `dst` is safe at the (possibly
non-chunk-aligned) offset `dst + got` because `Element`-pointer
arithmetic preserves each element's alignment: `AuthValueFerret` is a
`block`, and `AuthValueFp` is `alignas(16)` (its arithmetic does SIMD
`block` loads), so any element offset lands on a suitably aligned
element — the same direct-`next` contract `run()` relies on after its
own `drain_leftover`.

Usage — the caller owns the session (typically begin in its ctor, end
in its dtor):

```cpp
ote.begin();
ote.next_n(&one, 1);            // any count; refills a chunk internally
ote.next_n(batch.data(), k);    // round-end work amortizes over the whole session
ote.end();
```

Notes:
- It shares the same `leftover_` buffer as `run()`, so the two are
  **mutually exclusive** on one instance — pick streaming (`next_n` /
  `begin`/`next`/`end`) *or* one-shot (`run` / `rcot`), not both.
  In particular, `run()` rejects a call made while the streaming
  session is open.
- `enter_session_()` resets `leftover_count_ = 0`, so a fresh `begin()`
  never serves a stale tail from a previous session. (This is also why
  it composes with auto-rollover: the internal `end()`/`begin()` only
  fires when the buffer is empty mid-refill, so nothing is dropped.)
- The name is `next_n`, not an overload of `next`, on purpose: a
  subclass's `next(Element*)` override would otherwise hide a base
  `next(Element*, int64_t)` overload (C++ name hiding), forcing a
  `using` in every subclass. A distinct name avoids that.

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

## Auto-rollover inside next

The base declares `next()` as a pure virtual and does no rollover;
the subclass's `next()` override checks the session with the
always-on `expect_in_session_()` and implements the rollover. The check
runs once per produced chunk, not once per OT; normal chunks contain
thousands of OTs, so the expected branch is amortized over the batch. The
protocol-specific auto-rollover (calling end+begin transparently when
the round's user-visible budget is full) lives inside the subclass's
`next`:

```cpp
// Ferret::next (simplified)
void Ferret::next(block* out) {
    expect_in_session_();
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
    expect_in_session_();
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

`IOChannel` (in emp-tool) carries two optional per-direction
transcripts — a running send and recv digest held in a single `fs_`
variant, SHA-256 by default (the hash backend is selected at
`enable_fs` time) — that absorb every byte sent / received
once `enable_fs(send_first)` is called. Both must be called by
exactly one party with `send_first=true` (the other passes false).

Streaming extensions use FS in two ways:

1. **Per-protocol chi seeds.** Inside a malicious-mode `next` /
   `end`, the gadget snapshots `io->get_digest()` to derive
   chi vectors. The digest is computed deterministically from the
   wire bytes both parties have observed, so both parties get the
   same chi vector without an extra round of communication.

2. **Diagnostic per-direction digests.** `io->get_send_digest()`
   and `io->get_recv_digest()` return the running digest (SHA-256 by
   default) of each direction's transcript. The `trace_hash` test uses
   these to
   verify wire-byte equivalence across refactors. See
   [`wire-trace-hashes.md`](wire-trace-hashes.md).

Subclasses that need FS for chi seeds enable it lazily — e.g.
Ferret's `bootstrap_()` does `if (!io->fs_enabled()) io->enable_fs(is_ot_sender());`.
A protocol may also have FS pre-enabled by an outer harness; the
`if (!fs_enabled())` guard makes that a no-op.

## Destruction in-session

```cpp
~StreamingExtension() {
    expecting(!in_session_,
              "~StreamingExtension: destructed without calling end()");
}
```

A protocol object destructed in the middle of a session is a bug —
the leftover buffer may hold un-consumed bytes; the peer is waiting
for more. The base catches this with `emp::expecting` in all build
flavors (not just debug).
This is also the tripwire for a `next_n` caller that forgets to
`end()`: since `next_n` keeps the session open, the owner must close it
(e.g. in its destructor) before the extension is destroyed — `end()`
must run while the concrete subclass is still alive, so it can't be
called from `~StreamingExtension` itself (the override would already be
gone).

## What about `setup_done`?

`setup_done` is a public-on-the-base bool. Subclasses set it true
inside their lazy bootstrap. Setters that must fire pre-bootstrap
(`set_delta`, `set_choice_seed`, and `set_sid`) enforce
`!setup_done` with always-on `emp::expecting` checks. The base does not
check `setup_done` itself — it remains a contract implemented by each
subclass's bootstrap and configuration surface.

## See also

- [`class-organization.md`](class-organization.md) — who inherits
  from whom; where each carrier and gadget lives.
- [`wire-trace-hashes.md`](wire-trace-hashes.md) — using the FS
  digests to verify refactors don't change wire bytes.
