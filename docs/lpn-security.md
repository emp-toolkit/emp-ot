# LPN security parameters

This page states the assumption emp-ot's LPN-based protocols rest on, what each
parameter means, which parameter sets ship and where they live in the code, and
how they were chosen. The README's *LPN security* section is the short version.

Every cost below is the log₂ of an attack's operation count: time only, with no
memory charged. These are estimates against known attacks, not guarantees.

## 1. The assumption and the parameters

### The assumption

`Ferret`, `SilentFerret`, `F2kVOLE` and `FpVOLE` rest on **primal LPN with regular
noise over a 10-local code**. In each round, the samples

```
u = x·A + e
```

are assumed indistinguishable from uniform given the public matrix `A`, where:

- `x ∈ F^k` is a uniform secret.
- `A` has `k` rows and `N` columns. Each column sums `d = 10` pseudorandom rows,
  drawn with replacement, so over F₂ its weight is even and at most 10. This is a
  10-local linear code: Alekhnovich's sparse-matrix LPN assumption (FOCS 2003). For
  `F2kVOLE` each of those rows is first scaled by its own pseudorandom GF(2¹²⁸)
  element.
- `e ∈ F^N` is regular: the `N` coordinates split into `t` blocks of
  `2^tree_depth`, and each block has exactly one noisy entry at a uniform
  position, with value 1 over F₂ and a uniform field element otherwise.

In syndrome form this is the regular syndrome decoding (RSD) problem of the attack
literature, with `n = N`, `h = t` and block size `β = 2^tree_depth`. The target is
128 bits.

The field `F` is F₂ for `Ferret` and `SilentFerret`, F_p with p = 2⁶¹ − 1 for
`FpVOLE`, where a repeated row gives the coefficient 2, and GF(2¹²⁸) for `F2kVOLE`,
with the per-entry coefficients above. Over GF(2¹²⁸), 0/1 entries would let the
instance split into 128 binary instances, one per bit plane, sharing one noise
support; F_p has no such planes. The large-field figures cover `FpVOLE` and `F2kVOLE`
alike.

Semi-honest mode is plain regular LPN. Malicious mode is the "LPN with static
leakage" of Ferret (CCS 2020, eprint 2020/924, Def. 4): once per round (once per prepaid batch for
`SilentFerret`) the sender learns whether the chi-fold check passed, one
selective-failure query on the round's noise positions. The paper answers that
query before releasing outputs; `Ferret::next()` releases a round's COTs before
`end()` runs the check, so outputs must be treated as provisional until `check()`
or `end()` (README, *Streaming RCOT*).

### The parameters

`PrimalLPNParameter(t, logk, tree_depth)` fixes the instance. The three inputs:

| Parameter | Meaning | What it trades |
|---|---|---|
| `logk` | Dimension `k = 2^logk`. This is the LPN table, `16·k` bytes, which every sample reads at `d` random positions. | A larger table raises security and falls out of cache. |
| `tree_depth` | Noise block size `2^tree_depth`, which is also the depth of each cGGM tree. | One level deeper cuts the correction traffic by nearly half and lowers security. |
| `t` | Number of noise blocks, which is the noise weight and the number of cGGM trees per round. | A larger `t` gives longer rounds and lowers security. Traffic and compute per COT barely move. |

`d = 10` is fixed (`tuning::lpn_d`). The derived quantities:

| Quantity | Value | Meaning |
|---|---|---|
| `k` | `2^logk` | LPN dimension. |
| `N` | `t · 2^tree_depth` | Samples per round, all trees included. |
| `M` | `k + t · tree_depth + 128` | Base COTs a round consumes: the LPN secret, the cGGM choice bits and the chi check, in disjoint slots. |
| `refill_trees` | `⌈M / 2^tree_depth⌉` | Trees whose outputs become the next round's base COTs. They are not user-visible but are folded with the same secret, so an attacker is given all `N` samples. |
| COTs per round | `(t − refill_trees) · 2^tree_depth` | User-visible output of one round. |
| traffic per COT | `tree_depth · 128 / 2^tree_depth · t / (t − refill_trees)` bits | cGGM correction traffic. |

Each round uses a fresh secret and fresh matrix columns: the matrix PRG keeps
advancing across trees and rounds. The secret is the receiver's choice bits on the
`k` base COTs reserved for it, hidden by the bootstrap in the first round and by the
previous round's LPN in every later round.

## 2. The parameter sets and where they live

| Set | table | `t` | `logk` | `tree_depth` | `N` per round | `M` base COTs | COTs per round | bits/COT | lowest cost (bits) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ferret_b9` | 1 MiB | 2,400 | 16 | 9 | 1,228,800 | 87,264 | 1,141,248 | 2.42 | 144.2 |
| `ferret_b10` | 2 MiB | 2,800 | 17 | 10 | 2,867,200 | 159,200 | 2,707,456 | 1.32 | 141.3 |
| `ferret_b11` | 4 MiB | 3,800 | 18 | 11 | 7,782,400 | 304,072 | 7,477,248 | 0.716 | 142.8 |
| `ferret_b12` (default) | 8 MiB | 4,200 | 19 | 12 | 17,203,200 | 574,816 | 16,625,664 | 0.388 | 141.2 |
| `ferret_b13` | 16 MiB | 4,500 | 20 | 13 | 36,864,000 | 1,107,204 | 35,749,888 | 0.209 | 141.4 |

Bits/COT is the steady-state cGGM correction traffic. "Lowest cost" is the minimum
over every attack counted in §3, in both fields; §3 has the full tables.

In the code:

| What | Where |
|---|---|
| The five sets | `tuning::ferret_b9` … `tuning::ferret_b13` in [`emp-ot/tuning.h`](../emp-ot/tuning.h) |
| `PrimalLPNParameter`, its derived `k`, `M`, `refill_trees`, and `validate_primal_lpn_parameter` | [`emp-ot/tuning.h`](../emp-ot/tuning.h) |
| `d = 10` | `tuning::lpn_d` in [`emp-ot/tuning.h`](../emp-ot/tuning.h) |
| The matrix: `idx = r & (k−1)` from an AES-CTR PRG; for `F2kVOLE`, one GF(2¹²⁸) coefficient block per entry from the same stream | `Lpn` in [`emp-ot/common/lpn.h`](../emp-ot/common/lpn.h) |
| The matrix seed: `RO("emp-ot:ferret:lpn-seed", sid)`, or the `set_lpn_matrix_seed` root bound to `(t, logk, tree_depth)`; a fixed public constant for sVOLE | [`ferret.cpp`](../emp-ot/ot_extension/ferret/ferret.cpp), [`svole.h`](../emp-ot/svole/svole.h) |
| The noise: tree `i` owns block `i`, and its one nonzero entry sits at the bit-reversed cGGM puncture point, the complement of the receiver's base-COT choice bits for that tree | [`emp-ot/common/mp_gadget.h`](../emp-ot/common/mp_gadget.h) |
| The round loop and the slot layout of `M` | [`ferret.cpp`](../emp-ot/ot_extension/ferret/ferret.cpp), [`svole.h`](../emp-ot/svole/svole.h) |
| Choosing a set: the `param` constructor argument, `ferret_b12` by default | [`ferret.h`](../emp-ot/ot_extension/ferret/ferret.h), [`silent_ferret.h`](../emp-ot/ot_extension/ferret/silent_ferret.h), [`svole.h`](../emp-ot/svole/svole.h) |

Three quantities follow from the smallest set, and `tuning.h` derives the first two
from it:

| Constant | Value | Effect |
|---|---|---|
| Nest threshold, `ferret_bootstrap_nest_factor · ferret_b9.M` | 174,528 | A set with `M` above it bootstraps its first round from one round of a nested `ferret_b9` instance (`ferret_b11`–`ferret_b13`); the others bootstrap directly from `SoftSpoken<8>`. So the larger sets' security is also bounded by `ferret_b9`'s. |
| `softspoken_ferret_bootstrap_chunk_blocks` | 682 blocks, 87,296 OTs | `ferret_b9` bootstraps in one chunk and `ferret_b10` in two. |
| The `ferret_b9` round | 1,141,248 COTs, `N` = 1,228,800 | One round covers `M` of every larger set, and `FpVOLE`'s `t + k + 1` must fit in `N`. |

The sVOLE generators use the same sets with their own carried values:
`M_sVOLE = t + k + 1`. Both draw their cGGM base COTs from an inner `Ferret` at the
default set. `FpVOLE` always runs a `ferret_b9` pre-stage. `F2kVOLE` nests through
`ferret_b9` for `ferret_b11`–`ferret_b13` and Galois-packs directly for the others.

### Choosing your own parameters

`PrimalLPNParameter(t, logk, tree_depth)` accepts any shape with `logk, tree_depth ≤ 30` and
`0 < refill_trees < t`; the constructor checks arithmetic consistency, not security. The sets
are SECURITY-class for the auto-tuner ([`performance-tuning.md`](performance-tuning.md)), and
both parties must use the same set. To evaluate a set, feed `N = t·2^tree_depth`,
`k = 2^logk` and `t` to the estimator in `regular` mode and to
`python3 tools/lpn_security.py N k t` (§7).
Evaluate the exact `t` rather than interpolating, because costs step when the solving degree
changes (Step 3 of §3).

A custom set cannot change the stages underneath it:

- any `Ferret` set with `M` above twice `ferret_b9`'s bootstraps through a nested `ferret_b9`
  instance, one round while `M ≤ 1,141,248`;
- the sVOLE generators run the default `Ferret` set for their base COTs, and `F2kVOLE` nests
  through `ferret_b9` when its carry `t + k + 1` exceeds twice `ferret_b9`'s (135,874);
- `FpVOLE` runs a `ferret_b9` pre-stage, so its sets need `t + k + 1 ≤ 1,228,800`.

## 3. How the parameters were chosen

### The target

Every set keeps every counted attack at **141 bits or more, in both F₂ and the large
field**: 128 bits plus a 10% margin. One set serves both fields. The margin is there
because published costs for regular LPN keep falling; §6 shows what that did to
earlier sets.

### The papers used

The tool is the LPN estimator of Yu, Yang, Wang, A. Wang, T. Wang, Liu, Hao and Li
(<https://lpnestimator.com>, `Code_estimators` at commit 969ef60, with the overflow
fix of §7). Its routines, and the three more evaluated with `tools/lpn_security.py`:

| Attack | Source | Evaluated with |
|---|---|---|
| Pooled Gauss, SD, SD 2.0, SD-ISD and BJMM, on the exact-noise instance `(N − t, k − t, t)` over F₂ and on `(N, k, t)` over a large field | Liu, Wang, Yang, Yu, *The Hardness of LPN over Any Integer Ring and Field for PCG Applications*, EUROCRYPT 2024 (eprint 2022/712) | the estimator |
| Regular ISD: PER, ENU, REP, and the permutation variant over large fields | Esser, Santini, *Not Just Regular Decoding*, CRYPTO 2024 (eprint 2023/1568) | the estimator |
| Hybrid ISD/algebraic attack | Wang, Wang, Yang, Liu, Yu, Zhang, Wang, *A Hybrid Algorithm for the Regular Syndrome Decoding Problem*, ASIACRYPT 2025 (eprint 2025/1284) | the estimator |
| AGB 2.0 | Liu, Wang, Yang, Yin, Yu, *AGB 2.0* (eprint 2025/1476), building on Briaud, Øygarden, *A New Algebraic Approach to the Regular Syndrome Decoding Problem*, EUROCRYPT 2023 (eprint 2023/176) | the estimator |
| XFL and WXL at arbitrary degree | Furue, Aikawa, *Refined Application of the XL Algorithm within the Algebraic Approach to the Regular Syndrome Decoding Problem* (eprint 2026/2470) | `tools/lpn_security.py` |
| WXL over the sparse rows of a 10-local matrix | this page, built on Furue–Aikawa | `tools/lpn_security.py` |
| Restricted ISD: elimination on the samples inside a peeled coordinate set | this page, after the filtering step of Agrawal, Bagchi, Kumar, *Spectral Method attacks Sparse LWE, Sparse LPN and Beyond* (eprint 2026/614) | `tools/lpn_security.py` |

Cueto Noval, Merz, Stählin and Ünal, *On the Soundness of Algebraic Attacks against
Code-based Assumptions* (EUROCRYPT 2025, eprint 2025/415), supports the algebraic
heuristics these estimates rely on: the underlying assumptions hold asymptotically
for most parameter sets.

### Step 1: the table size

`logk` sets the table the LPN kernel gathers from. `bench_lpn`, ns per LPN output at
2²⁴ outputs, one core of an AMD EPYC 9R45 (Zen 5, `c8a.48xlarge`, idle, pinned), min
of 3 runs:

| table | 2¹⁶ | 2¹⁷ | 2¹⁸ | 2¹⁹ | 2²⁰ | 2²¹ | 2²² |
|---|---:|---:|---:|---:|---:|---:|---:|
| ns/output | 4.7 | 5.4 | 5.9 | 6.1 | 8.0 | 33.0 | 41.7 |

The 32 MiB table (`k = 2²¹`) falls off the 32 MiB-per-CCX L3, and the 16 MiB table
costs about 30% on the gather kernel. The family covers 1–16 MiB, with 8 MiB as the
default.

### Step 2: the tree depth

Correction traffic per LPN output is `tree_depth · 128 / 2^tree_depth`, so each level
nearly halves it. Security falls with `k / 2^tree_depth`, the expected number of noisy
positions among any `k` samples:

| `logk − tree_depth` | noisy positions among `k` samples | largest `t` at ≥ 141 bits (1 / 2 / 4 / 8 / 16 MiB) | refill share of a round | bits/COT |
|---:|---:|---|---|---|
| 6 | 64 | about 190 / 225 / 280 / 400 / 800 | 35 / 29 / 23 / 16 / 8% | 1.92 / 0.97 / 0.49 / 0.24 / 0.12 |
| 7 | 128 | 2,400 / 2,800 / 3,800 / 4,200 / 4,500 | 7.1 / 5.6 / 3.9 / 3.4 / 3.0% | 2.42 / 1.32 / 0.716 / 0.388 / 0.209 |
| 8 | 256 | not evaluated / 10,000 or more on the others | under 5% | about 1.8× the row above |

One level deeper reaches the floor only at a small `t`. Above the `t` in the table, BJMM over F₂ is
below the floor on the 1–8 MiB tables, at about 129 / 133 / 137 / 140 bits by `t = 800`, and the hybrid
attack falls further from about `t = 1,250`. At the `t` that holds the floor, refill takes 16–35% of every
round: 15–42% more work per COT in exchange for 21–37% less traffic. One level shallower clears the
floor with room at about 1.8× the traffic. The family keeps `logk − tree_depth = 7` on every table. The
rows for 6 and 8 come from the F₂ estimator and sparse WXL; the large-field routines were not run on all
of those shapes.

### Step 3: `t`

`t` is the largest multiple of 100 at which every counted attack costs at least 141
bits in both fields, with sparse rows counted at the 121-term bound described below.
The cost falls as `t` grows because more blocks give more quadratic equations per
monomial, which lowers the degree at which the algebraic system can be solved.

| Set | `t` | degree `d` | guess `(u, f)` | guess (bits) | block-sum share of rows | row weight `W` | linear algebra (bits) | cost at `t` | cost at `t + 100` |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ferret_b9` | 2,400 | 4 | (2, 630) | 15.3 | 4.7% | 340 | 128.8 | **144.2** | 140.4 |
| `ferret_b10` | 2,800 | 4 | (1, 135) | 4.1 | 3.4% | 437 | 137.2 | **141.3** | 138.0 |
| `ferret_b11` | 3,800 | 3 | (10, 3,691) | 29.4 | 2.0% | 492 | 113.4 | **142.8** | 140.7 |
| `ferret_b12` | 4,200 | 3 | (16, 546) | 23.9 | 0.0% | 121 | 117.3 | **141.2** | 139.3 |
| `ferret_b13` | 4,500 | 3 | (22, 3,183) | 18.0 | 0.0% | 121 | 123.3 | **141.4** | 139.4 |

The last two columns are the costs at `t` and at `t + 100`, so `t` is the last multiple of
100 above the floor. In every set the binding attack is WXL over sparse rows over F₂,
described below. Its cost splits into the guess, `u` noise-free positions per block and one
more on `f` blocks, and the linear algebra at degree `d`.

The degree thresholds explain where `t` lands at `logk − tree_depth = 7`. Without guessing,
degree 4 is reachable from `t` of about 2,800–3,000 and degree 3 from about 4,800–5,400,
depending on the table. With 121-term rows the linear algebra alone costs 127.3 / 135.3 /
143.3 / 151.3 / 159.3 bits at degree 4 and 99.3 / 105.3 / 111.3 / 117.3 / 123.3 at degree 3
across the five tables. On the 1 and 2 MiB tables degree 4 is below the floor on its own, so
`t` stays low enough that reaching degree 4 takes guessing. On the 4–16 MiB tables degree 4
clears the floor, so `t` goes past that point and stops where degree 3 with guessing reaches
141 bits.

Evaluate the exact `t` of a custom set rather than interpolating, because costs step when the
solving degree changes. AGB 2.0 over F₂ falls by 20–26 bits when its witness degree drops from
4 to 3: from 160.6 bits at `t = 4,700` to 139.8 at `t = 4,800` for `(logk, tree_depth) = (16, 9)`,
and from 173.5 bits at `t = 5,000` to 147.3 at `t = 5,100` for `(17, 10)`.

### The costs on the shipped sets

Binary instance, `regular` mode (bits; the lowest in each row in bold):

| set | Gauss | SD 2.0 | SD-ISD | BJMM | hybrid | PER | ENU | REP | AGB 2.0 | XFL | WXL | restricted ISD | sparse WXL |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ferret_b9` | 227.8 | 381.3 | 215.8 | 211.8 | 186.3 | 243.2 | 215.3 | 217.8 | 186.2 | 175.1 | 164.7 | 148.8 | **144.2** |
| `ferret_b10` | 232.7 | 386.8 | 222.0 | 217.9 | 189.8 | 249.1 | 221.7 | 225.2 | 196.4 | 177.9 | 164.8 | 148.3 | **141.3** |
| `ferret_b11` | 235.6 | 388.2 | 226.5 | 222.4 | 184.7 | 253.7 | 226.4 | 230.9 | 193.5 | 166.6 | 166.6 | 146.0 | **142.8** |
| `ferret_b12` | 239.2 | 391.0 | 231.5 | 227.4 | 187.4 | 258.0 | 231.4 | 235.9 | 203.7 | 168.6 | 168.2 | 146.6 | **141.2** |
| `ferret_b13` | 242.5 | 393.1 | 235.2 | 232.0 | 190.8 | 261.9 | 236.0 | 239.7 | 213.5 | 172.3 | 171.4 | 147.5 | **141.4** |

Large-field instance. Of the estimator's F_q routines, only SD 2.0 changes with `q` on
these sets, by under 0.02 bits between F_p and GF(2¹²⁸). The one-round AGB routine
`AGBforq` (the copy in `lwyy/hardness_of_lpn.py`, see §7) agrees with AGB 2.0 to within
0.01 bit on every set and has no column of its own.

| set | Gauss | SD 2.0 | SD-ISD | hybrid | reg-ISD | AGB 2.0 | XFL | WXL | restricted ISD | sparse WXL |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ferret_b9` | 234.8 | 395.9 | 234.8 | 193.5 | 250.3 | 192.2 | 181.9 | 171.6 | **148.8** | 149.5 |
| `ferret_b10` | 236.7 | 395.2 | 236.7 | 193.3 | 253.2 | 189.0 | 180.4 | 168.7 | 148.3 | **143.4** |
| `ferret_b11` | 238.3 | 393.8 | 238.3 | 186.3 | 256.4 | 183.6 | 169.3 | 169.3 | 146.0 | **143.3** |
| `ferret_b12` | 240.8 | 394.1 | 240.8 | 187.5 | 259.6 | 183.3 | 170.1 | 169.6 | 146.6 | **141.2** |
| `ferret_b13` | 243.4 | 394.7 | 243.4 | 189.9 | 262.7 | 185.1 | 173.1 | 172.2 | 147.5 | **141.4** |

Attack names: Gauss = Pooled Gauss; SD-ISD and BJMM = Liu–Wang–Yang–Yu; PER, ENU, REP
and reg-ISD = Esser–Santini; hybrid = Wang et al.; AGB 2.0 = Liu et al.; XFL and WXL =
Furue–Aikawa with a dense code; sparse WXL and restricted ISD = below.

### Evaluating Furue–Aikawa

The paper's XFL (its eq. 8) and WXL (eq. 9) costs were evaluated with `ω = 2.8`,
searching the guess parameters `(u, f, g)`: `u` noise-free positions per block, one
more on `f` blocks, and `g` blocks guessed whole. Over large fields the solving degree
comes from the paper's series. Over F₂ every linear form squares to itself, so the
reduced system satisfies Boolean relations. There the degree is the first
non-positive coefficient of

```
(1 + (β−u−2)z)^f · (1 + (β−u−1)z)^(h−g−f) · (1 + z)^(−(n−k)) / (1 − z)
```

which at `u = f = g = 0` is the series of Briaud–Øygarden's Modeling 2 times the `1 / (1 − z)` of
the affine Macaulay matrix. This series and the paper's large-field series matched the coranks of
small Macaulay matrices at degrees 2, 3 and 4, with 10-local matrices and on the guessing path, with
the deviations listed under *WXL over sparse rows* below. Three implementations of the F₂ costs,
written separately by AI models, agree to 0.1 bit. At the paper's listed parameters, the large-field
costs reproduce ten rows of its Table 2 and seven of its Tables 3 and 4 to within rounding.

### WXL over sparse rows

WXL's matrix–vector products are the only part of its cost that depends on row weight,
and the paper prices them for a dense code: about `k²/2` terms per row. emp-ot's matrix
is sparser than that in the right basis. Keep the LPN secret `x` as the unknowns. Each
noise coordinate is

```
e_j = u_j + Σ_{i ∈ S_j} x_i,    |S_j| ≤ 10
```

so a Macaulay row `m · e_a · e_b`, for `a ≠ b` in one block and a monomial `m` of degree
at most `d − 2`, has at most `11 · 11 = 121` terms. An invertible change of variables
preserves the rank at each degree, so the solving degree stays what the series says.

Over F₂ the block sums give one more kind of row, `m · (1 + Σ_{j ∈ B} e_j)`. It is dense by
comparison, with about `w_B = k · (1 − (1 − 2/k)^(10β)) / 2` terms: 4,741 / 9,481 / 18,961 /
37,921 / 75,841 across the five tables. So the attack adds only as many as the rank needs. The
degree `d` is the first non-positive coefficient of the series with all of them available,

```
(1 + (β−u−2)z)^f · (1 + (β−u−1)z)^(h−f) · (1 + z)^(−(n−k)) / (1 − z)
```

and the number of block-sum rows needed is `D`, the coefficient at `d` of the series without
them, or zero if that is not positive:

```
(1 + (β−u−1)z)^f · (1 + (β−u)z)^(h−f) · (1 + z)^(−(n−k)) / (1 − z)
```

Noise values are unknown over a large field, so there are no block sums and `D = 0`. The degree
there comes from

```
(1 + (β−u−2)z)^f · (1 + (β−u−1)z)^(h−f) · (1 − z)^(n−k−h−1)
```

A guessed noise-free position adds the row `e_j = 0`, with at most 11 terms, and keeps all
`N` columns. With block Wiedemann and the paper's accounting, the cost in bits is

```
−log₂ P + log₂(3 · W) + 2 · log₂ N
P = (1 − (u+1)/β)^f · (1 − u/β)^(h−f)
W = 121 + (D / N) · (w_B − 121)
N = Σ_{i ≤ d} C(k, i) over F₂, C(k + d, d) over a large field
```

On the shipped sets this is 21–31 bits below dense WXL in the same field. It applies to any
10-local matrix of this form, and a larger `d` is not a useful fix: doubling `d` to 20 adds only
about 2 bits at twice the kernel cost, so the sets lower `t` instead. Every column of `A` has even
weight over F₂, so `x` and `x ⊕ 1^k` give the same samples. The attack first fixes one coordinate of
`x`, because the kernel at the solving degree is otherwise large; this changes the cost by under 0.01
bits.

**What was checked.** These are exact ranks of Macaulay matrices in the `x` basis, with one variable
fixed and 10-local matrices. Two separately written programs ran them, each written by an AI model; no
outside cryptanalyst has reproduced them.

- **The series over F₂, without block-sum rows.** It gives the corank at every degree in 9 instances
  with `k` up to 256 at degree 2 and up to 80 at degree 3, in 18 more shapes at degree 3 with up to 63
  variables, and in 28 shapes at degree 4 with up to 33 variables and 46,938 columns. Row weight
  stays at or below 121, and the kernel vector gives the secret. There are three kinds of deviation.
  A predicted corank of 2 came out as 3 in two runs. One degree-4 run has corank 2 because its instance
  has a second regular solution. And `(n, k, h, β) = (72, 32, 18, 4)` at degree 4 has corank 2–3 from
  roots of the system without block sums that leave a block empty: about 2^0.8 are expected at that
  size, under 2^−1,000,000 on the shipped sets, and block-sum rows remove them.
- **Guessed and block-sum rows.** Guessed rows match in 9 of 9 runs at degree 3. Block-sum rows act as
  one more guessed position per block in 11 of 11 runs at degree 3. Adding only some of them lowers the
  corank row for row: `(192, 64, 24, 8)` at degree 3 has corank 2,752 with none, 1,752 with 1,000 and 1
  with 3,000, and the secret is recovered.
- **The large-field series.** Over F_p with p = 2³¹ − 1 it matches in 23 of 23 runs at degrees 3 and 4,
  including guessing.
- **Using about `N` rows.** A uniformly random `N + 300` rows have rank `N − 1`, and the kernel vector
  gives `x`, in 16 of 16 runs up to `N` = 46,938.
- **The costs.** The two programs agree to 0.01 bits on the shipped sets without block-sum rows. With
  them, the second program adds every block-sum row instead of only those the rank needs, and gets 145.3 /
  142.4 / 143.7 / 142.8 / 143.7 bits. The lower figures above are the ones used.

**What was not.** This analysis comes from this project and has not been peer-reviewed.

- **Scale.** The shipped sets have `k` of 2¹⁶–2²⁰ and `k/β = 128`. The checks stop at `k = 256` at degree
  2, `k = 80` at degree 3 and `k = 36` at degree 4, with `k/β` at most 32. The series, the row mix and the
  use of about `N` rows are extrapolated from there. Block Wiedemann itself was not run.
- **Degree 4 with guessing.** The 1 and 2 MiB tables use degree 4 with guessing and block-sum rows. Over
  F₂ guessing and block-sum rows were checked together only at degree 3. At degree 4, guessing was checked
  only over F_p, and block-sum rows on one shape.
- **Row weights.** The costs count each row at the 121-term bound. At average weights, 110.25 terms for
  `m · e_a · e_b` and 11 for a guessed row, the five sets cost 144.0 / 141.3 / 142.4 / 140.5 / 140.8 bits.
- **Constants and units.** A Wiedemann constant of 2.5 instead of 3 takes off 0.26 bits. The costs count
  single-bit XORs over F₂; counting 64-bit word XORs instead takes off 6 bits.
- **What did not help.** Eliminating the guessed variables shrinks `N` but fills in the rows, and with
  fill-in measured on simulated rows it is a net loss of 0.2–0.9 bits. Guessing whole blocks, restricting
  to a subset of the variables, and using the samples lightened by repeated indices gain nothing either.

### Restricted ISD

The filtering step of Agrawal, Bagchi and Kumar (eprint 2026/614, Algorithm 1) uses the
locality directly: keep a coordinate set `L` and only the samples whose support lies inside
it. Those samples involve only `x_L`, so `|L|` noise-free ones among them determine `x_L` by
elimination, and the rest of `x` then follows at much lower cost. The paper searches `x_L`
exhaustively, which at the `N/k` of 19–35 here needs `|L|` above `0.9·k`; at noise rate
`t/N = 2^−tree_depth`, elimination on noise-free samples is far cheaper.

`L` comes from greedy peeling of the public matrix: repeatedly drop the coordinate that
appears in the fewest surviving samples, and stop at the smallest `L` that still keeps `|L|`
samples. A random `L` keeps a fraction `(|L|/k)^10` of the samples and needs
`|L| = (N/k)^(−1/9)·k`, 0.67–0.72·`k` on these sets; greedy peeling needs 0.56–0.61·`k`.
The ratio was measured on random 10-local instances with each set's `N/k`, and was the same
at `k` = 2¹², 2¹⁴ and 2¹⁶ to within 0.002. A one-for-one swap search after peeling lowered
it by under 1%. On simulated instances the kept samples have rank `|L| − 1` or `|L| − 2`
(the all-ones vector is always in the kernel, because every column has even weight), so a
solve leaves at most a few candidates for `x_L`.

One attempt succeeds when all `|L|` samples are noise-free, with probability
`(1 − t/N)^|L|`. Attempts with other peelings share most of their samples, so they do not
raise that probability much on one instance, and the cost counts one solve, `3·10·|L|²` by
Wiedemann over rows of at most 10 terms, divided by it. The cost is the same in both fields.

| set | `\|L\|/k` | noise-free term | restricted ISD |
|---|---:|---:|---:|
| `ferret_b9` | 0.613 | 113.3 | 148.8 |
| `ferret_b10` | 0.600 | 110.8 | 148.3 |
| `ferret_b11` | 0.577 | 106.7 | 146.0 |
| `ferret_b12` | 0.570 | 105.3 | 146.6 |
| `ferret_b13` | 0.564 | 104.2 | 147.5 |

Restricted ISD sets no `t`: it stays 3.2–7.0 bits above each set's lowest cost (§2), which
is sparse WXL over F₂, although on `ferret_b9` it is the cheaper of the two over the large
field. It is this
project's analysis and is not peer-reviewed, and a better subset search than greedy peeling
would lower it.

### Papers not used for selection

These were read and do not set any parameter here.

- **Kim, Kim, Lee, Lee**, *Regular Syndrome Decoding Is Easier Than Previously Estimated*
  (eprint 2026/2563; code at <https://github.com/ho-chang/RSD_ReEstimate>). A two-stage
  guess–reduce–solve refinement of the hybrid attack with balanced per-block guessing. Its released
  cost search, in the binary model with `ξ(N) = 0.5·N`, gives 156.4 / 156.3 / 147.4 / 147.0 / 147.4
  bits on `ferret_b9` … `ferret_b13`. All five are above the floor, so it does not change any `t`.
- **Carrier, Hatey, Luzzi, Tillich**, *Multilevel Amortized Gaussian Elimination in Information-Set
  Decoding: Applications to HQC and PCG* (eprint 2026/1498), and **Kim, Lee**, *Reduce and Prange:
  Revisiting Prange's ISD for Solving LPN/RSD over Large Fields* (eprint 2024/276). Both speed up
  information-set decoding. The estimator's ISD routines cost 212 bits or more on these sets,
  more than 60 bits above the floor, so these were not evaluated separately.
- **Agrawal, Bagchi, Kumar**, *Algorithms for Sparse LWE and LPN with Small Secrets* (eprint
  2026/1550). Distinguishers for sparse LWE and LPN over Z_q whose secret has ℓ∞ norm at most
  `B`, built on short linear dependencies among the sparse rows, found by walks on a Kikuchi
  graph. For LPN noise they run in about `(8πBk/ε)^(l(1/2+ε))` time given about
  `(q − 1)^⌊d/2⌋ · (Ck/l)^⌈d/2⌉ · l log(Bk)` samples, or `(Ck/l)^d · l log(Bk)` samples, for a
  free parameter `l`. At `d = 10` and the `N/k` of 19–35 here, these need `l` of at least `0.84·k`
  and `0.93·k` even with `C = 1`, so the time is exponential in `k`. Over F_p the secret is
  uniform, so `B` is about `p/2`, and the first bound also carries a factor `(p − 1)^5`.

## 4. What these estimates do not cover

- **The matrix model.** The estimator routines and dense XFL/WXL assume a uniformly
  random `A`. Two counted attacks use the 10-local structure: sparse WXL, for cheaper
  matrix–vector products, and restricted ISD, to pick samples on a coordinate subset by
  greedy peeling. No tool here models any other use of locality.
- **Memory.** Every figure is time only. The binding attack needs Krylov vectors of
  `N` bits: 2⁵¹–2⁶³ bits (2⁵⁴ at the default) across the sets.
- **Heuristics.** The algebraic attacks assume the rank behaviour the series predicts.
  Small experiments and Cueto Noval et al. support this, but neither covers these sizes.
- **Leakage.** The malicious-mode selective-failure query of §1, and deployments sharing
  one matrix root and choice seed across several senders, are outside the single-instance
  model.

## 5. The sVOLE check mask

In malicious mode the `F2kVOLE`/`FpVOLE` receiver answers the round-final
chi-fold check with `x* = Σ_i β_i·χ_{α_i} + x₀` in the clear (`mp_gadget.h`,
typed check). The mask `x₀` is carry slot `t`, and nothing else reads it: of the
`t + k + 1` carried slots, `0` to `t − 1` seed the trees and `t + 1` to `t + k` are
the round's LPN secret (`svole.h`). `x*` is therefore one-time padded, and the
check reveals only whether it passed, the selective-failure query of §1. `Ferret`
masks its check with the 128 dedicated check COTs.

## 6. Parameter sets by release

| release | sets `(N, k, t)` or `(t, logk, tree_depth)` | estimator minimum (binding) |
|---|---|---|
| current | `ferret_b9` (2,400, 16, 9) · `b10` (2,800, 17, 10) · `b11` (3,800, 18, 11) · `b12` (4,200, 19, 12) · `b13` (4,500, 20, 13) | 183.3 or more in both fields; every counted attack ≥ 141 (§3) |
| `v1.0.0-alpha.1` | `ferret_b13` (1,900, 19, 13) · `b12` (1,520, 18, 12) · `b11` (1,170, 17, 11) · `b10` (850, 16, 10) | 128.2 · 128.1 · 128.2 · 128.6 (hybrid; BJMM for b10) |
| `0.2.4`–`0.3.0` | `ferret_b13` (10,485,760; 452,000; 1,280) · `b12` (10,268,672; 238,000; 2,507) · `b11` (10,180,608; 124,000; 4,971), with setup sets (470,016; 32,768; 918) · (268,800; 17,384; 1,050) · (178,944; 17,384; 699) | 125.3 · 104.5 · 92.8 (hybrid); setup 119.8 · 113.7 · 124.0 |
| `0.1.0`–`0.2.3` | (10,608,640; 589,824; 1,295) with setup (649,728; 36,288; 1,269), within 2% of the CCS'20 sets of the attack literature (10,805,248; 589,760; 1,319) / (609,728; 36,288; 1,269), whose 609,728 is a Ferret-paper typo for 649,728 | the CCS'20 sets: 149.9 main, 126.6 setup (hybrid) |

The `v1.0.0-alpha.1` sets cost 112.8 · 111.3 · 113.1 · 120.6 bits under the sparse WXL
of §3 (`b13` · `b12` · `b11` · `b10`), and its default costs 130.3 under dense XFL/WXL over F₂.

In every 0.1.0–0.3.0 release the extension round reuses base COTs across
roles: cGGM choice bits occupy slots `[0, t·log_bin)`, the chi check
`[0, 128)`, the LPN secret `[128, 128 + k)`, so the first `t·log_bin − 128`
secret coordinates are also noise-position bits; the setup round is
disjoint, and the legacy LPN matrix seed is sampled by one party and sent
in the clear. The legacy estimates above assume the standard instance. The
`v1.0.0-alpha.1` sets have `logk − tree_depth = 6` and the `0.3.x` sets
were chosen against the Liu–Wang–Yang–Yu estimator of 2022, before the
regular-ISD, hybrid and AGB 2.0 attacks. The sets shape the transcript:
both parties must run the same release.

## 7. Reproducing the estimates

### The estimator

```bash
git clone https://github.com/1234wangtr/Code_estimators && cd Code_estimators
git checkout 969ef60
# apply the hybrid_quick.py fix below, then:
python3 console.py N=17203200 k=524288 t=4200 regular      # ferret_b12, F_2 (all routines)
python3 console.py N=36864000 k=1048576 t=4500 regular     # ferret_b13
```

Two things to know about the tool at these sizes:

- The F_q entry point (`q=...`) takes `AGBforq` from `agb2/agb2.py`, whose search reaches
  `f = 0, mu = β`. With the degree at 4 or below there, that evaluates `0·log 0`, which raises
  `decimal.InvalidOperation` and aborts the run on `ferret_b11`, `ferret_b12` and
  `ferret_b13`. The copy in `lwyy/hardness_of_lpn.py` stops one short and runs on every set,
  in about 2 minutes on `ferret_b9` and 40 on `ferret_b13`. The remaining routines (the
  per-field lists used for §3) can be called directly:

  ```python
  from lwyy.hardness_of_lpn import Gauss, SD_ISD_q, SDforq, SD2forq
  from hybrid.hybrid_quick import hybrid_bigq_quick
  from esser.regular_ISD import permutation_based_concrete_cost_bigq
  from agb2.agb2 import OurAGB2forq
  N, k, t, q = 17203200, 524288, 4200, (1 << 61) - 1
  for f in (lambda: Gauss(N, k, t), lambda: SD_ISD_q(N, k, t, q), lambda: SDforq(N, k, t),
            lambda: SD2forq(N, k, t, q), lambda: hybrid_bigq_quick(N, k, t),
            lambda: permutation_based_concrete_cost_bigq(N, k, t), lambda: OurAGB2forq(N, k, t)):
      print(f())
  ```

- As published, `hybrid/hybrid_quick.py` raises `OverflowError` in
  `log2(G1 + G2 + G3 * (2 ** try_comp))` on every shipped set except `ferret_b9`. The figures here use a
  log-domain form of that sum, which returns the same value wherever the original is
  finite. Add this helper and replace the expression, at its four occurrences, with
  `_log2sum3(G1, G2, G3, try_comp)`:

  ```python
  def _log2sum3(G1, G2, G3, try_comp):
      a = log2(G1) if G1 > 0 else -1e9
      b = log2(G2) if G2 > 0 else -1e9
      c = (log2(G3) if G3 > 0 else -1e9) + try_comp
      m = max(a, b, c)
      return m + log2(2 ** (a - m) + 2 ** (b - m) + 2 ** (c - m))
  ```

The F₂ routine `OurAGB2for2` is the slow one: 9 s on `ferret_b13`, 20 s on `ferret_b12`,
18 minutes on `ferret_b11`, 81 minutes on `ferret_b10` and about 3 hours on `ferret_b9`, on one laptop core.
The other routines finish within minutes.

### Furue–Aikawa, sparse WXL and restricted ISD

[`tools/lpn_security.py`](../tools/lpn_security.py) computes the Furue–Aikawa XFL and WXL
costs, sparse WXL and restricted ISD, over F₂ and over a large field, with the searches behind §3. It needs
only the Python standard library. With no arguments it reads the sets from
[`emp-ot/tuning.h`](../emp-ot/tuning.h) and prints the XFL, WXL, sparse WXL and restricted ISD
columns of §3, about four minutes on one laptop core:

```bash
python3 tools/lpn_security.py                         # the shipped sets
python3 tools/lpn_security.py 17203200 524288 4200    # one instance: N k t
python3 tools/lpn_security.py 17203200 524288 4200 --d 0   # dense code: XFL and WXL only
```

`N` must be a multiple of `t`; the block size is `N / t`. `--d` sets the column weight of
the code that sparse WXL and restricted ISD assume, 10 by default as in emp-ot's matrix. The script does not
include the estimator's routines, which have to be run as above.
