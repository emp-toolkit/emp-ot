# Adding a protocol

Three common extension shapes, in rough order of frequency:

1. **A new sVOLE carrier** (new field or new arithmetic) — define an
   `AuthValueXxx` and you're done; the existing `Svole<>`,
   `MultiPointGadget<>`, and `Lpn<>` templates pick it up.
2. **A new OT extension** (new RCOT construction) — subclass
   `OTExtension` and implement the per-role hooks.
3. **A new base OT** (new chosen-input OT) — subclass `OT` (or
   `RandomCOT`) and implement `send` / `recv`.

Each below walks you through the checklist. The last section covers
the *cross-cutting* changes any new protocol needs:
trace-hash registration, README baseline update, and tests.

For background on what these classes are, see
[`class-organization.md`](class-organization.md); for what they're
extending, see [`streaming-api.md`](streaming-api.md).

---

## 1. New sVOLE carrier (a new field or wire shape)

This is the most common case — you want sVOLE over a different field
(say a different Mersenne prime, a different F_2^k), or you want a
different wire shape (e.g. ship something other than `secret_sum:F`
per tree). Both are expressed as new `AuthValueXxx` types.

### 1a. Decide the storage

A carrier is a struct. Two storage shapes:

```cpp
// sVOLE-style (val + mac).
struct AuthValueXxx {
    using F = ...;
    F val;
    F mac;
    ...
};

// RCOT-style (mac only — no per-leaf value).
struct AuthValueXxx {
    using F = ...;
    F mac;
    ...
};
```

The order matters: val-first is the convention everything else
follows (emp-zk's `VAL`/`MAC` accessors, the `AuthValue`-as-packed-int
casts in `ostriple.h`). Don't reorder.

### 1b. Required members

The full contract, in the order generic code uses them. See
`emp-ot/svole/f2k_vole.h` (`AuthValueF2k`) and `emp-ot/svole/fp_vole.h`
(`AuthValueFp`) for working references.

```cpp
struct AuthValueXxx {
  using F = ...;                                                // (a)
  /* val, mac storage as above */                               // (b)

  // (c) Field arithmetic
  static F f_zero();
  static F f_add(F, F);
  static F f_sub(F, F);
  static F f_mul(F, F);

  // (d) Wire-format traits
  static constexpr bool          kHasSecretSum;
  static constexpr bool          kClearLeafLSB;
  static constexpr ChiFoldFlavor kChiFoldFlavor;  // F2kPacked | FTyped

  // (e) cGGM-leaf-to-element
  static AuthValueXxx auth_from_block(block leaf);

  // (f) Chi-fold helpers
  static void expand_chi(block chi_seed, F* chi_out, int64_t sz);
  static void accumulate_VW(F& VW_slot, const F* chi,
                            const AuthValueXxx* leaves, int64_t sz);

  // (g) LPN ops (for Lpn<AuthValueXxx, 10>)
  static constexpr int kLpnSafeAddsPerReduce;
  static void auth_add_into(AuthValueXxx&, const AuthValueXxx&);
  static void auth_partial_reduce(AuthValueXxx&);
  static void auth_final_reduce  (AuthValueXxx&);

  // (h) sVOLE protocol hooks  (only if used with Svole<>)
  static constexpr int delta_holder_party();
  static F resolve_delta(Ferret*);
  static void on_set_delta(F, Ferret*);
  struct Bootstrap {
    static void run(Svole<AuthValueXxx>&);
  };
};
```

Notes:

- **(c) field arithmetic.** Stick to the minimal set you actually
  use. `AuthValueFerret` only defines `f_zero` / `f_add` — the
  FTyped-only `f_mul` / `f_sub` callers don't instantiate for it
  (gated by `kChiFoldFlavor`). Add only what the gadget actually
  reaches for your wire-format-traits combination.

- **(d) wire-format traits.** Pick all three carefully — they decide
  what the multi-point gadget puts on the wire:

  | Trait | `false` semantics | `true` semantics |
  |---|---|---|
  | `kHasSecretSum` | No per-tree `secret_sum` byte; receiver α-fills from cGGM LSB-clear closure (RCOT-style). | Sender ships `secret_sum:F` per tree; receiver α-fills via `triple_yz − secret_sum − Σ_{j≠α} mac`. |
  | `kClearLeafLSB` | cGGM `build_sender` / `eval_receiver` write leaves as-is. | cGGM clears the per-leaf LSB (RCOT choice-bit encoding). |
  | `kChiFoldFlavor=F2kPacked` | n/a | Round-end check ships `bool[128] x_prime + 2-block hash`. Uses Galois packing on a 128-COT chi-check region. |
  | `kChiFoldFlavor=FTyped`    | n/a | Round-end check ships `F x_star + 1-block hash`. Uses field-typed accumulators. |

  The current pairings:
  - Ferret-style: `kHasSecretSum=false`, `kClearLeafLSB=true`, `F2kPacked`.
  - Mpsvole-style: `kHasSecretSum=true`, `kClearLeafLSB=false`, `FTyped`.

  Other combinations *might* work but haven't been validated — pick
  one of the two established pairings unless you're also writing a
  new run_end body in `mp_gadget.h`.

- **(e) `auth_from_block`.** Only called inside the gadget's
  `kHasSecretSum=true` branch. If your carrier has `kHasSecretSum=false`
  you can omit it (`AuthValueFerret` does).

- **(f) chi-fold helpers.** Both are only used in malicious mode.
  - `expand_chi`: turn the FS chi seed into `chi[leave_n]`. Ferret
    uses `PRG(seed).random_block(...)` directly; F2k/Fp hash the
    seed then `uni_hash_coeff_gen` it into field elements. Match
    whichever is appropriate for your `kChiFoldFlavor`.
  - `accumulate_VW`: `VW[idx] = Σ chi[i] · mac(leaves[i])`. The fast
    path uses Galois inner product (`vector_inn_prdt_sum_red`); the
    generic loop form is fine for Fp.

- **(g) LPN ops.** `kLpnSafeAddsPerReduce` is the number of `auth_add_into`
  calls between `auth_partial_reduce`s. For F_2 (XOR-only, no carry)
  set it to `INT_MAX`. For Mersenne F_p (~8-add carry budget) it's 5,
  giving a 5+5 split with d=10. `auth_partial_reduce` / `auth_final_reduce`
  are no-ops on XOR fields and real reductions on F_p.

- **(h) sVOLE hooks.** Only needed if the carrier is plugged into
  `Svole<>`. RCOT-only carriers (like `AuthValueFerret`) skip this.
  - `delta_holder_party()` returns `ALICE` or `BOB` — which party
    holds Δ at the outer-protocol level. For F_2k convention is BOB;
    for F_p it's ALICE. The choice flows through to the inner-Ferret
    role assignment.
  - `resolve_delta(Ferret*)` is the holder's default Δ if the user doesn't
    call `Svole::set_delta`. F_2k pulls Ferret's auto-sampled block
    Δ; F_p samples a canonical nonzero field element.
  - `on_set_delta(F, Ferret*)` propagates Δ into the inner Ferret if
    the two need to share it. F_2k bool-decomposes the F-typed Δ and
    forwards to `Ferret::set_delta` (requires `LSB(Δ) = 1`); F_p validates
    that Δ is canonical and nonzero but does not propagate it (Fp's Δ is
    independent of Ferret's and has no LSB constraint).
  - `Bootstrap::run(svole)` is the lazy setup body. Owns the
    initial-round seed sVOLE pairs. See `f2k_vole.h` (Galois packing
    with optional nested Svole) and `fp_vole.h` (COPE + Base_svole +
    pre-stage MPFSS+LPN) for the two existing flavors.

### 1c. Wire it up

```cpp
// emp-ot/svole/myfield_vole.h
#include "emp-ot/common/mp_gadget.h"   // for ChiFoldFlavor
#include "emp-ot/svole/svole.h"

namespace emp {

struct AuthValueMyField {
  /* ... all of (a)–(h) above ... */
};

// Optional: domain-named alias matching the existing F2kVOLE/FpVOLE pattern.
template <typename AuthValue = AuthValueMyField>
using MyFieldVOLE = Svole<AuthValue>;

} // namespace emp
```

That's it for the type. Add `#include "emp-ot/svole/myfield_vole.h"`
wherever consumers need it (test, emp-ot.h umbrella).

### 1d. Why this works without touching the gadget / Lpn / Svole

`Svole<AuthValue>`, `MultiPointGadget<AuthValue>`, and
`Lpn<AuthValue, d>` only see the carrier through its compile-time
trait constants and static methods. As long as your carrier
satisfies the contract above, the templates instantiate cleanly.
`if constexpr` branches inside `mp_gadget.h` pick the right wire
shape based on your trait values.

---

## 2. New OT extension (RCOT-style)

If you're adding a new RCOT construction (a new IKNP-flavor extension,
say) — i.e. a class with the `RandomCOT` API that uses base OTs to
produce many RCOTs — the recipe is to subclass `OTExtension`.

### 2a. Decide your dispatch shape

Subclasses override `begin / next / end` directly — no NVI hook
layer. The choice is how the override is structured:

- **Inline party-dispatch.** Have `begin/next/end` start with
  `if (is_ot_sender())` and delegate to private non-virtual helpers
  (`send_begin_/send_next_/send_end_` and the receiver pair). Choose
  this when sender and receiver bodies are genuinely different
  protocols (e.g. IKNP, SoftSpoken).

- **Unified body.** Have `begin/next/end` contain one body each and
  party-dispatch inside private per-stage helpers. Choose this when
  send/recv share the same shape up to a party test (e.g. Ferret).

In both shapes the override must:
1. Call `enter_session_()` at the top of `begin()`.
2. Call `expect_in_session_()` at the top of `next()` and `end()`.
3. Call `exit_session_()` at the bottom of `end()`.

These protected helpers (inherited from `StreamingExtension`) keep
the session tripwire honest without an NVI dispatcher layer.

### 2b. Boilerplate

```cpp
// emp-ot/ot_extension/myiknp.h
#include "emp-ot/ot_extension/ot_extension.h"
#include "emp-ot/base_ot/csw.h"   // your chosen base OT

namespace emp {

using MyIKNPBaseOT = CSW;   // pick a malicious-secure base OT

class MyIKNP : public OTExtension {
public:
    explicit MyIKNP(int party, IOChannel* io, bool malicious = true,
                    std::unique_ptr<OT> base_ot = nullptr)
        : OTExtension(party, io, malicious,
                      base_ot ? std::move(base_ot)
                              : std::unique_ptr<OT>(new MyIKNPBaseOT(io))) {}

    int64_t chunk_size() const override { return /* per-next() batch */; }

    void begin() override {
        enter_session_();
        if (is_ot_sender()) send_begin_();
        else                recv_begin_();
    }
    void next(block* out) override {
        expect_in_session_();
        if (is_ot_sender()) send_next_(out);
        else                recv_next_(out);
    }
    void end() override {
        expect_in_session_();
        if (is_ot_sender()) send_end_();
        else                recv_end_();
        exit_session_();
    }

private:
    void send_begin_();
    void send_next_(block* out);
    void send_end_();
    void recv_begin_();
    void recv_next_(block* out);
    void recv_end_();
};

} // namespace emp
```

### 2c. Lazy bootstrap

`send_begin_` (or the unified `begin` body for Ferret-shape protocols)
is the first place the protocol runs — flip `setup_done` true inside
the first call:

```cpp
void MyIKNP::send_begin_() {
    if (!setup_done) {
        // run the bootstrap: base_ot->send/recv, seed PRGs, etc.
        // (use `delta_bool[]` for Δ-side, `choice_prg` for choice-bit
        // side — both are inherited from OTExtension)
        if (malicious && !io->fs_enabled())
            io->enable_fs(/*send_first=*/is_ot_sender());
        setup_done = true;
    }
    // per-session reset
    if (malicious) /* reset chi-fold accumulators */;
}
```

The `io->fs_enabled()` guard makes it safe to be called when an outer
protocol has already enabled FS. Both branches should reach
`enable_fs` with the same `send_first` value across parties — the
canonical choice is `is_ot_sender()`.

### 2d. Use cGGM / Lpn / MultiPointGadget if you can

Most new RCOT constructions decompose into "build a puncturable PRF
+ amplify with LPN". The shared kernels are:

- `namespace emp::cggm` (`common/cggm.h`) — Half-Tree cGGM (puncturable
  PRF over `block`). Builders write to `block*` directly.
- `MultiPointGadget<AuthValueXxx>` (`common/mp_gadget.h`) — wraps cGGM
  + per-tree wire correction + malicious-mode chi-fold. Templated on
  the carrier.
- `Lpn<AuthValueXxx, d>` (`common/lpn.h`) — d-sparse LPN amplifier.

A new RCOT that fits the multi-point-then-LPN shape looks structurally
just like Ferret — see `emp-ot/ot_extension/ferret/ferret.cpp` for the
begin/next/end pattern with five protected helpers.

---

## 3. New base OT (chosen-input)

Base OTs subclass `OT` (or `RandomCOT` if you want native RCOT
output). The four existing ones (`CO`, `CSW`, `PVW`,
`BMM`) all subclass `OT` and provide:

```cpp
class MyBaseOT : public OT {
public:
    explicit MyBaseOT(IOChannel* io, /* whatever else you need */);

    void send(const block* data0, const block* data1, int64_t length) override;
    void recv(block* data, const bool* b, int64_t length) override;

    bool is_malicious_secure() const override { return true; }  // or false
};
```

That's the whole API. `OT::send_cot` / `recv_cot` and the `send_rot`
/ `recv_rot` helpers come from the base. If your protocol is RCOT-native
(produces correlated outputs without a chosen-input phase), inherit
from `RandomCOT` instead and override `rcot(block*, int64_t)` — the
single role-implicit RCOT entry on `RandomCOT`.

If you want OT extensions to default to your base OT, add a typedef
alongside the extension:

```cpp
// emp-ot/ot_extension/myiknp.h
using MyIKNPBaseOT = MyBaseOT;
```

The extension's ctor falls back to `MyIKNPBaseOT` when the caller
passes `base_ot = nullptr`.

---

## 4. (Rare) Adding a new chi-fold flavor

The two existing flavors (`F2kPacked`, `FTyped`) are hardcoded as a
`ChiFoldFlavor` enum in `common/mp_gadget.h`. Adding a third means:

- Extend the enum.
- Add a third `run_end_<flavor>` method on both
  `MultiPointGadgetSender` and `MultiPointGadgetReceiver`, gated by
  the new flavor's `static_assert`.
- Add the wire/algebra details for the new check.
- Pick which existing carriers (if any) should opt in.

This is invasive — a new flavor means a new round-final
consistency-check protocol. Don't reach for it unless you're
implementing something the two existing ones genuinely can't
express. If you do, also update [`wire-trace-hashes.md`](wire-trace-hashes.md)'s
baseline; the new flavor's hash will differ.

---

## 5. Cross-cutting changes any new protocol needs

After the type is defined and tests pass locally:

### 5a. Register a trace-hash entry

Open `test/trace_hash.cpp` and add a `measure(...)` call alongside
the existing ones:

```cpp
measure(party, port, "MyIKNP " + mode, rcot_sf, [&](NetIO* io){
    run_rcot(io, party, rcot_len,
        [&](IOChannel* x, bool m) {
            return std::unique_ptr<MyIKNP>(new MyIKNP(party, x, m));
        }, mali);
});
```

For sVOLE carriers:

```cpp
measure(party, port, "MyFieldVOLE " + mode, myfield_sf, [&](NetIO* io){
    run_svole<MyFieldVOLE<>>(io, party, svole_len, mali,
        [](auto& sv){ sv.set_delta(/* deterministic non-zero */); });
});
```

Pick `send_first` to match the protocol's own internal `enable_fs`
convention so the pre-enable is a no-op (RCOT: `is_ot_sender()`;
sVOLE: `is_delta_holder()`).

### 5b. Update the README baseline

After verifying with `EMP_TEST_MODE=1 ./run ./build/trace_hash`, paste
the new line into the `### Wire-trace hashes` table in
[`README.md`](../README.md). This is the baseline future refactors
compare against.

### 5c. Write a correctness test

If your protocol is an OT extension, follow the shape of
`test/test_choice_seed.cpp` or `test/test_ferret.cpp` —
exercise sender + receiver, verify the COT correlation (`K = m ⊕ b·Δ`).

For a sVOLE carrier, follow `test/test_f2k_vole.cpp` or
`test/test_fp_vole.cpp` — exercise the streaming path and the
one-shot path, then run the authenticated-triple check (`K = mac + Δ·val`).

RCOT uses `verify_rcot` in `test/test.h`; the sVOLE shape uses a
per-file `check_triple` helper (see `test/test_f2k_vole.cpp` /
`test/test_fp_vole.cpp`).

### 5d. Register the test in CMake

```cmake
# test/CMakeLists.txt
add_test_case_with_run(test_my_protocol)
```

`add_test_case_with_run` builds the binary AND registers it for
`ctest` as a two-party run via the `run` script.

### 5e. Optional: add to `emp-ot.h` umbrella

If consumers should be able to pull your header via the umbrella
`#include "emp-ot/emp-ot.h"`, add the include line.

---

## Quick reference: what files to touch

| Adding... | Header(s) | Test additions | Baseline |
|---|---|---|---|
| sVOLE carrier | `emp-ot/svole/<myfield>_vole.h` (new) | `test/test_<myfield>_vole.cpp` + CMakeLists entry; one line in `trace_hash.cpp` | README hash table |
| OT extension | `emp-ot/ot_extension/<myiknp>.{h,cpp}` (new) + CMake source list | maybe `test/test_<myiknp>.cpp`; one line in `trace_hash.cpp` | README hash table |
| Base OT | `emp-ot/base_ot/<mybase>.h` (new) | a `bench_base_ot.cpp` row; one line in `trace_hash.cpp` | README hash table |
| Chi-fold flavor | `emp-ot/common/mp_gadget.h` (extend) + all carriers that opt in | trace_hash will catch it | README hash table (all affected protocols' rows change) |

## See also

- [`class-organization.md`](class-organization.md) — class layout the
  templates rest on.
- [`streaming-api.md`](streaming-api.md) — the begin/next/end
  lifecycle your subclass plugs into.
- [`wire-trace-hashes.md`](wire-trace-hashes.md) — how the baseline
  is used to catch wire-format regressions.
