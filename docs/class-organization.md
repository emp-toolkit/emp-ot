# Class organization

The repo has two protocol families (OT extensions and sVOLE
extensions) sharing one streaming skeleton, one inner sibling-OT
gadget, one LPN amplifier, and one Half-Tree cGGM. This doc is the
map: who inherits from whom, who templates over what, and where each
responsibility lives.

## Top-level layout

```
emp-ot/
├── common/                ← shared by OT-extension and sVOLE-extension layers
│   ├── streaming_extension.h    StreamingExtension<Element>
│   ├── mp_gadget.h              MultiPointGadget{Sender,Receiver}<AuthValue>
│   ├── lpn.h                    Lpn<AuthValue, d>
│   └── cggm.h                   namespace cggm { build_sender, eval_receiver }
│
├── ot.h                   OT / COT / RandomCOT abstract interfaces
├── tuning.h               PrimalLPNParameter + tuned constants
│
├── base_ot/               OT (chosen-input) implementations
│   ├── co.h                     CO         (Chou-Orlandi)
│   ├── csw.h                    CSW        (CSW "blazing-fast")
│   ├── pvw.h                    PVW        (Peikert-Vaikuntanathan-Waters)
│   ├── bmm.h                    BMM        (Badrinarayanan-Masny-Mukherjee, post-quantum)
│   └── mlkem/                   shared ML-KEM-512 algebra + bmm.cpp impl
│
├── ot_extension/          RandomCOT extensions
│   ├── ot_extension.h           OTExtension base
│   ├── iknp.{h,cpp}             IKNP
│   ├── softspoken/              SoftSpoken<k, kChunkBlocks>
│   └── ferret/                  Ferret (+ AuthValueFerret carrier)
│
└── svole/                 sVOLE
    ├── svole.h                  Svole<AuthValue> + svole_n / svole_M
    ├── f2k_vole.h               AuthValueF2k (carrier + Bootstrap)
    ├── fp_vole.h                AuthValueFp  (carrier + Bootstrap)
    ├── fp_base_svole.h          Base_svole + Cope (Fp-only bootstrap helpers)
    └── fp_utility.h             Mersenne 2^61-1 arithmetic
```

## The two protocol families share one streaming base

```
                  StreamingExtension<Element>
                ┌───────────────────────────────┐
                │  pure virtuals (subclass):    │
                │    begin / next / end /       │
                │    chunk_size                 │
                │  non-virtual one-shot:        │
                │    run(data, num)             │
                │  state:                       │
                │    party, malicious,          │
                │    setup_done,                │
                │    leftover buffer            │
                │  tripwire helpers (protected):│
                │    enter_session_ /           │
                │    exit_session_  /           │
                │    assert_in_session_         │
                └───────────────────────────────┘
                              ▲
                              │
              ┌───────────────┴───────────────┐
              │                               │
   public RandomCOT, public                Svole<AuthValue>
   StreamingExtension<block>               : public StreamingExtension<AuthValue>
   (OTExtension)
              │
   ┌──────────┼──────────┬─────────────────┐
   │          │          │                 │
  IKNP    SoftSpoken  Ferret
                <k>
```

`StreamingExtension<Element>` (in `common/streaming_extension.h`) is
the only place the begin/next/end lifecycle, leftover buffer, and FS
plumbing live. Both protocol families share it; their concrete
classes differ in `Element` (`block` for RCOT, `AuthValueXxx` for
sVOLE) and the protocol-specific surface they add on top.

## OTExtension and its subclasses

```
OTExtension : public RandomCOT, public StreamingExtension<block>
├── public
│   ├── base_ot                 (owned base OT for bootstrap)
│   ├── Δ, delta_bool[128]      (sender-side correlation)
│   ├── choice_prg              (receiver-side PRG)
│   ├── set_delta(bool*)        (override Δ pre-bootstrap)
│   ├── set_choice_seed(block)  (override choice PRG seed)
│   ├── chunk_size()            (inherited; subclass overrides)
│   ├── begin/next/end          (inherited; subclass overrides)
│   └── rcot(data, num)         (RandomCOT abstract; final override —
│                                forwards to inherited run())
│
└── three subclasses (each overrides begin / next / end directly —
    no NVI hooks; tripwire enforced via the inherited
    enter_session_ / exit_session_ / assert_in_session_ helpers)
    ├── IKNP                    (inline party-dispatch to
    │                            send/recv_{begin,next,end}_)
    ├── SoftSpoken<k, kChunkBlocks>  (same shape as IKNP)
    └── Ferret                  (unified body per stage; party-dispatch
                                 inside the per-tree helpers)
```

**Subclass choice — inline party-dispatch vs unified body.** IKNP and
SoftSpoken have genuinely different code paths for sender vs receiver
(different base OT directions, different per-row work), so their
`begin/next/end` each start with `if (is_ot_sender())` and delegate
to private non-virtual `send_*_` / `recv_*_` helpers. Ferret's
send/recv bodies are the same shape up to a party-test (both run a
multi-point gadget + LPN slice loop), so its `begin/next/end` have
one unified body each, and the per-tree helpers
(`bootstrap_/inner_run_begin_/process_one_tree_/inner_run_end_/run_refill_`)
party-dispatch internally.

## Svole — one template, two carriers, two policies

```
Svole<AuthValue> : public StreamingExtension<AuthValue>
                                                       ▲
                                  AuthValue determines │
                                  every protocol detail
                                                       │
              ┌────────────────────────────────────────┼────────────────────────────────┐
              │                                                                         │
       AuthValueF2k                                                              AuthValueFp
       (in f2k_vole.h)                                                          (in fp_vole.h)
       block val, mac                                                           uint64 val, mac
       F = block, F_2k arithmetic (XOR, gfmul)                                  F = uint64, Mersenne mod p
       Bootstrap: Galois packing of M·128 Ferret COTs                           Bootstrap: COPE seed sVOLE
       delta_holder = BOB                                                       + pre-stage MPFSS+LPN
                                                                                delta_holder = ALICE
                                                                                resolve_delta = 0 (user must set)
```

`F2kVOLE` and `FpVOLE` are `using` aliases over `Svole<AuthValueF2k>`
and `Svole<AuthValueFp>` respectively.

## The carrier (AuthValueXxx) is the protocol description

`Svole`, `MultiPointGadget`, and `Lpn` are all templated on the
carrier. The carrier provides everything those generic classes need
in one place:

```
struct AuthValueXxx {
  using F = ...;                                    // field type
  F val;   F mac;                                   // storage (Ferret omits .val)

  // Field arithmetic
  static F f_zero / f_add / f_sub / f_mul ...

  // Wire-format / protocol traits
  static constexpr bool          kHasSecretSum;
  static constexpr bool          kClearLeafLSB;
  static constexpr ChiFoldFlavor kChiFoldFlavor;    // F2kPacked | FTyped

  // Chi-fold helpers
  static void expand_chi(block seed, F* out, int64_t n);
  static void accumulate_VW(F& acc, const F* chi,
                            const AuthValueXxx* leaves, int64_t n);

  // LPN ops (for Lpn<AuthValueXxx, d>)
  static constexpr int kLpnSafeAddsPerReduce;
  static void auth_add_into / auth_partial_reduce / auth_final_reduce;

  // cGGM leaf to element
  static AuthValueXxx auth_from_block(block leaf);

  // sVOLE-specific (Svole<AuthValue> only)
  static constexpr int delta_holder_party();
  static F resolve_delta(Ferret*);
  static void on_set_delta(F, Ferret*);
  struct Bootstrap { static void run(Svole<...>&); };
};
```

There are three concrete carriers:

| Carrier            | Lives in                  | F        | val | mac | Traits |
|--------------------|---------------------------|----------|-----|-----|--------|
| `AuthValueFerret`  | `ot_extension/ferret/ferret.h` | `block`  | no  | yes | `kHasSecretSum=false`, `kClearLeafLSB=true`, `F2kPacked` |
| `AuthValueF2k`     | `svole/f2k_vole.h`        | `block`  | yes | yes | `kHasSecretSum=true`,  `kClearLeafLSB=false`, `FTyped` |
| `AuthValueFp`      | `svole/fp_vole.h`         | `uint64` | yes | yes | `kHasSecretSum=true`,  `kClearLeafLSB=false`, `FTyped` |

Ferret's carrier is unusual: it's a single `block mac` field
(layout-equivalent to `block` so the gadget reinterprets directly).
There's no `val` because Ferret RCOT doesn't have a per-leaf value —
the choice bit is encoded in the LSB.

## The inner gadget: MultiPointGadget

Both Ferret and Svole run a sequence of cGGM trees and ship a
per-tree correction on the wire. That logic lives in
`MultiPointGadget{Sender,Receiver}<AuthValue>` (`common/mp_gadget.h`),
templated on the carrier. The carrier's `kHasSecretSum`,
`kClearLeafLSB`, and `kChiFoldFlavor` traits select compile-time
branches:

```
                    MultiPointGadgetSender<AuthValue>
                              │
            ┌─────────────────┴─────────────────┐
            │                                   │
  cGGM build with                      kHasSecretSum?
  AuthValue::kClearLeafLSB             ├── true:  ship c[d] + secret_sum:F
                                       └── false: ship c[d] only

                              │
                              │ (malicious only)
                              ▼
                       AuthValue::expand_chi → chi[leave_n]
                       AuthValue::accumulate_VW → VW[tree_idx]

  run_end_packed   ◄── F2kPacked chi-fold (Ferret style)
                       sender ships bool[128] x_prime + 2-block hash;
                       receiver derives x_prime from XOR(chi_α) + chi-check region

  run_end_typed    ◄── FTyped chi-fold (Mpsvole style)
                       sender: vb = Δ·x_star + triple_t.mac + Σ VW
                       receiver: x_star = Σ chi_α·val + triple.val
```

Aliases on Ferret's side keep the legacy names:

```cpp
using MPCOT_Sender   = MultiPointGadgetSender<AuthValueFerret>;
using MPCOT_Receiver = MultiPointGadgetReceiver<AuthValueFerret>;
```

## LPN and cGGM are pure helpers

`Lpn<AuthValue, d>` (in `common/lpn.h`) is the linear-code amplifier
that turns the sparse output of the multi-point gadget into a dense
correlation. It's templated on the carrier; the carrier provides
`auth_add_into / auth_partial_reduce / auth_final_reduce` and the
`kLpnSafeAddsPerReduce` integer that controls reduce frequency.

`namespace emp::cggm` (in `common/cggm.h`) is the Half-Tree cGGM tree
build/eval. It's a free-function namespace, no class, no
templating on AuthValue — it just writes `block` leaves. Used by
`MultiPointGadget` (and historically by SoftSpoken's PPRF tree).

## Putting it together: data-flow for a single sVOLE round

```
   svole.run(out, num)
      │
      ▼
   StreamingExtension::run                                  (common/)
      ├── drain leftover
      └── begin → loop next → end
                              │
   Svole::do_begin / do_next / do_end                       (svole/svole.h)
      ├── do_begin:  bootstrap_ (lazy)
      │              swap carry_curr_/_next_
      │              inner_run_begin_ (pull base COTs from base_ferret_,
      │                                set Δ on gadget_send_)
      ├── do_next:   process_one_tree_(out)
      │                │
      │                ├── gadget_send_->run_next_tree       (common/mp_gadget.h)
      │                │       cGGM build, ship c[]+secret_sum, accumulate VW
      │                │
      │                └── lpn_->compute_slice               (common/lpn.h)
      │                       fold LPN secret from carry_curr_ into dst
      │
      └── do_end:    run_refill_ (refill trees write into carry_next_)
                     inner_run_end_ (chi-fold check via gadget_send_->run_end_typed)
```

For Ferret RCOT the picture is the same with these substitutions:
`Svole` → `Ferret`, `carry_*` → `ot_pre_data_*` (raw block storage),
`gadget_*` is a `MultiPointGadget<AuthValueFerret>` (= `MPCOT_*`),
`lpn_` is `Lpn<AuthValueFerret, 10>`.

## See also

- [`streaming-api.md`](streaming-api.md) — the
  begin/next/end/run/leftover lifecycle in detail.
- [`wire-trace-hashes.md`](wire-trace-hashes.md) — how to verify a
  refactor didn't move any wire bytes.
