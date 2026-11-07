#!/usr/bin/env python3
"""Attack-cost estimates for primal LPN with regular noise, as used to select the
Ferret parameter sets (docs/lpn-security.md).

For an instance of N samples, dimension k and t noise blocks of beta = N/t positions
(exactly one noisy position per block), this prints, over F2 and over a large field:

  XFL, WXL    Furue and Aikawa (eprint 2026/2470), Theorem 2, for a dense code; over F2
              with the Boolean series of docs/lpn-security.md, "Evaluating Furue-Aikawa".
  sparse WXL  WXL over the sparse rows of a d-local code, where each column of the matrix
              sums d pseudorandom rows (docs/lpn-security.md, "WXL over sparse rows").
  restricted  Gaussian elimination on the samples supported inside a coordinate set chosen
              by greedy peeling, for a d-local code, in either field (docs/lpn-security.md,
              "Restricted ISD"). The peeling ratio is measured on a scaled random instance.

Costs are log2 of an operation count, time only. The lpnestimator.com routines are not
included; run them as well (docs/lpn-security.md, section 7).

  python3 tools/lpn_security.py                 the sets in emp-ot/tuning.h
  python3 tools/lpn_security.py N k t [--d D]   one instance; D = column weight of the
                                                code (default 10), 0 for a dense code
"""
import heapq
import random
import re
import sys
from collections import Counter
from math import comb, log2
from pathlib import Path

OMEGA = 2.8  # linear-algebra exponent for the XFL elimination steps
DMAX = 14    # highest degree of the truncated Hilbert series
GMAX = 6     # most blocks guessed outright (g) in XFL / WXL

# ---- truncated power series in z, as coefficient lists of length DMAX + 1

def mul(a, b):
    r = [0] * (DMAX + 1)
    for i, x in enumerate(a):
        if x == 0:
            continue
        for j, y in enumerate(b):
            if i + j > DMAX:
                break
            r[i + j] += x * y
    return r

def pow1pxz(x, e):  # (1 + x z)^e, e >= 0
    return [comb(e, j) * x**j if j <= e else 0 for j in range(DMAX + 1)]

def pow1mz(e):      # (1 - z)^e, any integer e
    if e >= 0:
        return [(-1)**j * comb(e, j) if j <= e else 0 for j in range(DMAX + 1)]
    return [comb(-e + j - 1, j) for j in range(DMAX + 1)]

def pow1pz_neg(m):  # (1 + z)^(-m), m >= 0
    return [(-1)**j * comb(m + j - 1, j) for j in range(DMAX + 1)]

def first_nonpositive(s, lo=2):
    return next((d for d in range(lo, DMAX + 1) if s[d] <= 0), None)

def lsum(*xs):      # log2 of a sum of 2^x terms; None terms are skipped
    xs = [x for x in xs if x is not None]
    m = max(xs)
    return m + log2(sum(2.0**(x - m) for x in xs))

def lg(x):
    return log2(x) if x > 0 else None

def guess_log2p(beta, t, u, f, g=0):
    # log2 of the probability that the noise avoids the u (or u+1, on f blocks)
    # guessed-noise-free positions of every block that is not guessed outright
    return f * log2(1 - (u + 1) / beta) + ((t - g - f) * log2(1 - u / beta) if u else 0.0)

def search(t, k, cost, umax, fgrid, gs=(0,)):
    """Minimise cost(u, f, g) -> (bits, ...) or None: a coarse grid over f for every u
    and g, refined to single steps around each coarse optimum."""
    fs = sorted(set([0, 1, 2, 3, 5, 8, 10, 12, 20, 50, 100] + [t * j // fgrid for j in range(fgrid + 1)]))
    best = None
    for g in gs:
        for u in range(umax + 1):
            bu = None
            for f in fs:
                c = cost(u, f, g) if f <= t else None
                if c and (bu is None or c < bu):
                    bu = c
            if bu is None:
                continue
            step = max(1, t // fgrid)
            while True:
                f0 = bu[2]
                for f in range(max(0, f0 - step), min(t, f0 + step) + 1, max(1, step // 4)):
                    c = cost(u, f, g)
                    if c and c < bu:
                        bu = c
                if step == 1:
                    break
                step = max(1, step // 4)
            if best is None or bu < best:
                best = bu
    return best

# ---- Furue-Aikawa XFL and WXL, large field (Theorem 2, series (5))

def fa_series(n, k, h, beta, u, f, g, gblocks=True):
    a, b = beta - u - 1, beta - u
    e = n - k - h - 1 if gblocks else n - k - (h - g) - 1
    return mul(mul(pow1mz(e), pow1pxz(a - 1, f)), pow1pxz(b - 1, h - g - f))

def fa_cost_q(n, k, h, u, f, g, variant):
    beta = n // h
    if u > beta - 2 or f + g > h or (u + 1) * f + u * (h - g - f) + beta * g >= k:
        return None
    d = first_nonpositive(fa_series(n, k, h, beta, u, f, g))
    if d is None:
        return None
    a, b, nk = beta - u - 1, beta - u, n - k
    n1 = n - (u + 1) * f - u * (h - g - f)
    if nk < f * a:  # blocks eliminated by the n - k linear equations, a-sized first
        L = nk // a; c1, c2, r = f - L - 1, h - g - f, (L + 1) * a - nk
    else:
        rem = nk - f * a; L2 = rem // b
        c1, c2, r = 0, h - g - f - L2 - 1, (L2 + 1) * b - rem
        if c2 < 0:
            return None
    base = mul(mul(pow1pxz(r - 1, 1), pow1pxz(a - 1, c1)), pow1pxz(b - 1, c2))
    nb = 1 + c1 + c2
    M = mul(base, pow1mz(-(nb + 1)))
    Mp = mul(mul(base, pow1pxz(beta - 1, g)), pow1mz(-(nb + g + 1)))
    Mpp = mul(base, pow1mz(-(nb + g + 1)))
    x = (nk // beta) * (beta - u - 1)
    T13 = nk * (nk - x) * (n1 - x)
    lP1, lP2 = guess_log2p(beta, h, u, f, g), -g * log2(beta)
    if variant == 'WXL':
        return -lP1 + lsum(lg(T13), log2(3) + log2(Mpp[2]) + 2 * log2(Mpp[d]) - lP2), u, f, g, d
    sa = fa_series(n, k, h, beta, u, f, g, gblocks=False)
    if sa[d] > 0:  # core block not column-full-rank at d: the XFL preprocessing does not apply
        return None
    t1 = OMEGA * log2(M[d])
    t2 = 2 * log2(M[d]) + log2(max(Mp[2] - M[2], 1)) if Mp[2] > M[2] else None
    t3 = log2(M[d]) + log2(-sa[d]) + log2(Mp[d] - M[d]) if (sa[d] < 0 and Mp[d] > M[d]) else None
    T23 = OMEGA * log2(Mpp[d] - M[d]) - lP2 if Mpp[d] > M[d] else None
    return -lP1 + lsum(lg(T13), lsum(t1, t2, t3), T23), u, f, g, d

# ---- Furue-Aikawa over F2: one variable per block eliminated by the block's sum-to-one
# equation, field equations kept, and each linear form contributes 1/(1+z)

def fa_series_f2(n, k, h, beta, u, f, g, variant, with_g=True):
    a, b = beta - u - 2, beta - u - 1
    s = mul(mul(mul(pow1pz_neg(n - k), pow1mz(-1)), pow1pxz(a, f)), pow1pxz(b, h - g - f))
    if with_g and variant != 'WXL':
        s = mul(s, pow1pxz(1, g))
    return s

def fa_cost_f2(n, k, h, u, f, g, variant):
    beta = n // h
    if u > beta - 3 or f + g > h or (u + 1) * f + u * (h - g - f) + (beta - 1) * g >= k - h:
        return None
    d = first_nonpositive(fa_series_f2(n, k, h, beta, u, f, g, variant))
    if d is None:
        return None
    a, b, nk = beta - u - 2, beta - u - 1, n - k
    n1 = n - h - (u + 1) * f - u * (h - g - f)
    if a <= 0:
        return None
    if nk < f * a:
        L = nk // a; c1, c2, r = f - L - 1, h - g - f, (L + 1) * a - nk
    else:
        rem = nk - f * a; L2 = rem // b
        c1, c2, r = 0, h - g - f - L2 - 1, (L2 + 1) * b - rem
        if c2 < 0:
            return None
    base = mul(mul(pow1pxz(r, 1), pow1pxz(a, c1)), pow1pxz(b, c2))
    C = pow1mz(-1)
    M = mul(base, C)
    Mp = mul(mul(base, pow1pxz(beta - 1, g)), C)
    Mpp = M if variant == 'WXL' else mul(mul(base, pow1pxz(1, g)), C)
    x = (nk // (beta - 1)) * (beta - u - 2)
    T13 = nk * max(nk - x, 1) * max(n1 - x, 1)
    lP1, lP2 = guess_log2p(beta, h, u, f, g), -g * log2(beta)
    if variant == 'WXL':
        return -lP1 + lsum(lg(T13), log2(3) + log2(Mpp[2]) + 2 * log2(Mpp[d]) - lP2), u, f, g, d
    sa = fa_series_f2(n, k, h, beta, u, f, g, variant, with_g=False)
    if sa[d] > 0:
        return None
    t1 = OMEGA * log2(M[d])
    t2 = 2 * log2(M[d]) + log2(Mp[2] - M[2]) if Mp[2] > M[2] else None
    t3 = log2(M[d]) + log2(-sa[d]) + log2(Mp[d] - M[d]) if (sa[d] < 0 and Mp[d] > M[d]) else None
    T23 = OMEGA * log2(Mpp[d] - M[d]) - lP2 if Mpp[d] > M[d] else None
    return -lP1 + lsum(lg(T13), lsum(t1, t2, t3), T23), u, f, g, d

def furue_aikawa(n, k, t, field, variant):
    beta = n // t
    if field == 'F2':
        return search(t, k, lambda u, f, g: fa_cost_f2(n, k, t, u, f, g, variant),
                      min(beta - 3, k // t + 2), 48, range(GMAX + 1))
    return search(t, k, lambda u, f, g: fa_cost_q(n, k, t, u, f, g, variant),
                  min(beta - 2, k // t + 2), 48, range(GMAX + 1))

# ---- WXL over the sparse rows of a d-local code. With the LPN secret as the unknowns,
# each noise coordinate has at most d secret terms, so a row m*e_a*e_b has at most
# (d+1)^2 terms; an invertible change of variables leaves the solving degree unchanged.
# Over F2, block-sum rows m*(1 + sum of the block's e_j) act as one more guessed position
# per block; only as many are added as the rank needs, D = the series without them at d.

def sparse_cost(n, k, t, field, d_local, u, f):
    beta = n // t
    if (u + 1) * f + u * (t - f) >= k:
        return None
    w0 = (d_local + 1)**2
    lp = guess_log2p(beta, t, u, f)
    if field == 'F2':
        without = mul(mul(mul(pow1pz_neg(n - k), pow1mz(-1)), pow1pxz(beta - u - 1, f)), pow1pxz(beta - u, t - f))
        full = mul(mul(mul(pow1pz_neg(n - k), pow1mz(-1)), pow1pxz(beta - u - 2, f)), pow1pxz(beta - u - 1, t - f))
        d = first_nonpositive(full)
        if d is None:
            return None
        nmon = sum(comb(k, i) for i in range(d + 1))
        # weight of a block-sum row: XOR of beta columns of d_local uniform rows each
        w_block = k * (1 - (1 - 2 / k)**(d_local * beta)) / 2
        w = w0 + max(0, without[d]) / nmon * (w_block - w0)
    else:
        s = mul(mul(pow1mz(n - k - t - 1), pow1pxz(beta - u - 2, f)), pow1pxz(beta - u - 1, t - f))
        d = first_nonpositive(s)
        if d is None:
            return None
        nmon, w = comb(k + d, d), w0
    return -lp + log2(3 * w) + 2 * log2(nmon), u, f, 0, d

def sparse_wxl(n, k, t, field, d_local):
    beta = n // t
    return search(t, k, lambda u, f, g: sparse_cost(n, k, t, field, d_local, u, f),
                  min(beta - 3, k // t + 2), 96)

# ---- restricted ISD. Keep a coordinate set L and only the samples whose support lies inside
# it; once there are |L| of them, |L| noise-free samples determine x on L. L comes from greedy
# peeling (repeatedly drop the coordinate in the fewest surviving samples), which only reads
# the public matrix. One attempt succeeds when all |L| samples are noise-free, so the cost is
# the solve divided by that probability; repeated attempts reuse most of the same samples and
# cannot do better on one instance. The ratio |L|/k depends on N/k and d but not on k, so it
# is measured on a random d-local instance of dimension SIM_K with the same N/k.

SIM_K = 1 << 14

def peeling_ratio(n_over_k, d_local, sim_k=SIM_K, seed=1):
    rnd = random.Random(seed)
    n = round(n_over_k * sim_k)
    cols = []
    for _ in range(n):  # d draws with replacement; a row drawn twice cancels
        cnt = Counter(rnd.randrange(sim_k) for _ in range(d_local))
        cols.append([v for v, m in cnt.items() if m % 2])
    inc = [[] for _ in range(sim_k)]
    for j, s in enumerate(cols):
        for v in s:
            inc[v].append(j)
    deg = [len(x) for x in inc]
    alive, removed = [True] * n, [False] * sim_k
    heap = [(deg[v], v) for v in range(sim_k)]
    heapq.heapify(heap)
    nalive, size, best = n, sim_k, None
    while heap:
        dv, v = heapq.heappop(heap)
        if removed[v] or dv != deg[v]:
            continue
        if nalive >= size:
            best = size
        removed[v], size = True, size - 1
        for j in inc[v]:
            if alive[j]:
                alive[j], nalive = False, nalive - 1
                for w in cols[j]:
                    if not removed[w]:
                        deg[w] -= 1
                        heapq.heappush(heap, (deg[w], w))
    return best / sim_k

def restricted_isd(n, k, t, d_local):
    r = peeling_ratio(n / k, d_local)
    l = r * k
    # all l samples noise-free, at noise rate t/n; solve by Wiedemann, 3l products of
    # rows with at most d_local terms
    return -l * log2(1 - t / n) + log2(3 * d_local * l * l), r

# ---- driver

def evaluate(n, k, t, d_local):
    row = {}
    for field in ('F2', 'large'):
        for v in ('XFL', 'WXL'):
            row[(field, v)] = furue_aikawa(n, k, t, field, v)
        row[(field, 'sparse')] = sparse_wxl(n, k, t, field, d_local) if d_local else None
    row[('both', 'restricted')] = restricted_isd(n, k, t, d_local) if d_local else None
    return row

def tuning_sets():
    src = (Path(__file__).resolve().parent.parent / 'emp-ot' / 'tuning.h').read_text()
    sets = re.findall(r'PrimalLPNParameter (ferret_b(\d+))\s*=\s*PrimalLPNParameter\((\d+),\s*(\d+),\s*(\d+)\)', src)
    return [(name, int(t) << int(dp), 1 << int(lk), int(t)) for name, _, t, lk, dp in sorted(sets, key=lambda s: int(s[1]))]

def main(argv):
    d_local = 10
    if '--d' in argv:
        i = argv.index('--d'); d_local = int(argv[i + 1]); argv = argv[:i] + argv[i + 2:]
    if argv and argv[0] in ('-h', '--help'):
        print(__doc__); return
    if argv:
        if len(argv) != 3:
            sys.exit(__doc__)
        n, k, t = (int(x.replace(',', '').replace('_', '')) for x in argv)
        instances = [(f"N={n:,} k={k:,} t={t:,}", n, k, t)]
    else:
        instances = tuning_sets()
    for _, n, k, t in instances:
        if t <= 0 or n % t or n <= k:
            sys.exit(f"need N divisible by t and N > k (got N={n}, k={k}, t={t})")
    cols = [(f, v) for f in ('F2', 'large') for v in ('XFL', 'WXL', 'sparse')] + [('both', 'restricted')]
    print(f"bits; sparse and restricted assume a {d_local}-local code" if d_local else "bits; dense code")
    names = {('both', 'restricted'): 'restricted'}
    print(f"{'instance':<34}" + ''.join(f"{names.get((f, v), ('F2' if f == 'F2' else 'Fq') + ' ' + v):>11}" for f, v in cols) + f"{'lowest':>9}")
    for name, n, k, t in instances:
        row = evaluate(n, k, t, d_local)
        vals = [row[c][0] if row[c] else None for c in cols]
        cells = ''.join(f"{v:>11.1f}" if v is not None else f"{'-':>11}" for v in vals)
        low = min(v for v in vals if v is not None)
        print(f"{name:<34}{cells}{low:>9.1f}")
        for c in cols:
            if row[c] and row[c][0] == low:
                if c[1] == 'restricted':
                    print(f"{'':<34}lowest: restricted ISD at |L| = {row[c][1]:.3f}·k")
                else:
                    _, u, f, g, d = row[c]
                    print(f"{'':<34}lowest: {c[0]} {c[1]} at u={u}, f={f}, g={g}, degree {d}")
                break
        if row[('both', 'restricted')]:
            print(f"{'':<34}restricted ISD keeps |L| = {row[('both', 'restricted')][1]:.3f}·k")

if __name__ == '__main__':
    main(sys.argv[1:])
