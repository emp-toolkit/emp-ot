// Per-phase compute decomposition for SoftSpokenOT<8> rcot streaming.
// Runs each phase of one chunk's worth of work in isolation, no
// network IO, and reports ns/OT for each phase.
//
// Phases (rcot_recv_next side, sender role of OT — the heavier path):
//   sfvole_send : n=16 calls of sfvole_sender_compute_chunk per chunk
//                 (the per-leaf AES + fold; on NEON k=8 this is the
//                 butterfly path landed in eb3bd79).
//   d_buf_xor   : compute d_i = u_canonical ⊕ u_temp for i ∈ [1, n).
//   conv        : sse_trans_n128 of the planes_chunk → bs*128 OT blocks.
//   chi_fold    : malicious-mode per-chunk gfmul + GaloisFieldPacking
//                 (skipped when not in malicious mode).
//
// Phases (rcot_send_next side, receiver role of OT):
//   sfvole_recv : n=16 calls of sfvole_receiver_compute_chunk.
//   apply_derand: XOR d_i into w_planes for set bits of α_i.
//   conv        : same as sender.
//   chi_fold    : malicious-mode (skipped in semi-honest).
//
// Compare per-phase ns/OT against e2e ns/OT from test_softspoken to
// see which fraction is kernel vs IO/sync.

#include <emp-tool/emp-tool.h>
#include "emp-ot/softspoken/softspoken_ot.h"
#include "emp-tool/crypto/f2k.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using namespace emp;

namespace {

double now_us() {
    using clk = std::chrono::high_resolution_clock;
    return std::chrono::duration<double, std::micro>(
               clk::now().time_since_epoch())
        .count();
}

template <typename F>
double bench_median_us(int iters, int trials, F&& fn) {
    std::vector<double> samples((size_t)trials);
    for (int t = 0; t < trials; ++t) {
        double t0 = now_us();
        for (int i = 0; i < iters; ++i) fn();
        samples[(size_t)t] = (now_us() - t0) / iters;
    }
    std::sort(samples.begin(), samples.end());
    return samples[(size_t)trials / 2];
}

}  // namespace

int main() {
    constexpr int k = 8;
    constexpr int n = SoftSpokenOT<k>::n;     // 128 / 8 = 16
    constexpr int Q = 1 << k;                 // 256
    const int64_t bs = SoftSpokenOT<k>::kChunkBlocks;  // 1024 at k=8
    const int64_t chunk_OTs = bs * 128;       // 131,072 OTs / chunk

    std::printf("# bench_softspoken_phase — Apple M decomposition\n");
    std::printf("# k=%d n=%d Q=%d bs=%lld chunk_OTs=%lld\n\n",
                k, n, Q, (long long)bs, (long long)chunk_OTs);

    PRG prg(fix_key);

    // ----- inputs -----
    std::vector<block> leaves((size_t)n * Q);
    prg.random_block(leaves.data(), n * Q);
    std::vector<int> alphas((size_t)n);
    for (int i = 0; i < n; ++i) alphas[i] = (int)(i * 17) & (Q - 1);

    const uint64_t session = 0xc0ffeeULL;
    const int64_t b0 = 0;

    // ----- scratch (matches rcot_*_next layout) -----
    std::vector<block> planes_chunk((size_t)n * k * bs);  // 128 * bs blocks
    std::vector<block> d_bufs((size_t)(n - 1) * bs);
    std::vector<block> u_canonical((size_t)bs);
    std::vector<block> u_temp((size_t)bs);
    std::vector<block> out((size_t)chunk_OTs);

    // Pre-fill d_bufs with random data so apply_derand has realistic input.
    prg.random_block(d_bufs.data(), (n - 1) * bs);

    // =================================================================
    // Phase: sfvole_sender (recv-side of OT runs sfvole_sender × n).
    // =================================================================
    auto fn_sfvole_send = [&]() {
        for (int i = 0; i < n; ++i) {
            block* v_i = planes_chunk.data() + (size_t)i * k * bs;
            block* u_dst = (i == 0) ? u_canonical.data() : u_temp.data();
            softspoken::sfvole_sender_compute_chunk<k>(
                leaves.data() + (size_t)i * Q,
                session, b0, bs, u_dst, v_i);
        }
    };

    // =================================================================
    // Phase: sfvole_receiver (send-side of OT runs sfvole_receiver × n).
    // =================================================================
    auto fn_sfvole_recv = [&]() {
        for (int i = 0; i < n; ++i) {
            block* w_i = planes_chunk.data() + (size_t)i * k * bs;
            softspoken::sfvole_receiver_compute_chunk<k>(
                alphas[i], leaves.data() + (size_t)i * Q,
                session, b0, bs, w_i);
        }
    };

    // =================================================================
    // Phase: d_buf compute (rcot_recv_next).
    // d_i = u_canonical ⊕ u_temp, n-1 of them.
    // =================================================================
    auto fn_dbuf = [&]() {
        for (int i = 1; i < n; ++i) {
            block* d_i = d_bufs.data() + (size_t)(i - 1) * bs;
            for (int64_t bb = 0; bb < bs; ++bb)
                d_i[bb] = u_canonical[bb] ^ u_temp[bb];
        }
    };

    // =================================================================
    // Phase: apply_derand (rcot_send_next).
    // Per sub-VOLE i ≥ 1 with set bit b of α_i, XOR d_i into plane b.
    // =================================================================
    auto fn_derand = [&]() {
        for (int i = 1; i < n; ++i) {
            block* w_i = planes_chunk.data() + (size_t)i * k * bs;
            const block* d_i = d_bufs.data() + (size_t)(i - 1) * bs;
            softspoken::apply_derand_to_w_planes<k>(alphas[i], d_i, bs, w_i);
        }
    };

    // =================================================================
    // Phase: Conv (sse_trans_n128).
    // =================================================================
    auto fn_conv = [&]() {
        sse_trans_n128(reinterpret_cast<uint8_t*>(out.data()),
                       reinterpret_cast<const uint8_t*>(planes_chunk.data()),
                       /*ncols=*/bs * 128);
    };

    // =================================================================
    // Phase: malicious chi-fold (per chunk).
    // Mirrors combine_send_chunk: bs F_{2^128} mults + GaloisFieldPacking
    // per chunk.
    // =================================================================
    GaloisFieldPacking packer;
    block check_q = zero_block;
    block Delta = makeBlock(0LL, 1LL);
    auto fn_chi_send = [&]() {
        block Q_i, chi, tmp;
        // Use a fresh PRG seed each call to avoid the compiler optimizing
        // the loop away.
        PRG chi_prg(&Delta);
        for (int64_t i = 0; i < bs; ++i) {
            packer.packing(&Q_i, out.data() + 128 * i);
            chi_prg.random_block(&chi, 1);
            gfmul(chi, Q_i, &tmp);
            check_q = check_q ^ tmp;
        }
    };

    // =================================================================
    // Run.
    // =================================================================
    const int trials = 5;
    auto report = [&](const char* name, double us, bool include_in_total) {
        double per_ot_ns = us * 1000.0 / chunk_OTs;
        std::printf("%-15s  %10.2f us  (%6.3f ns/OT)%s\n",
                    name, us, per_ot_ns, include_in_total ? "" : "  [N/A]");
    };

    auto t_send  = bench_median_us( 5, trials, fn_sfvole_send);
    auto t_recv  = bench_median_us( 5, trials, fn_sfvole_recv);
    auto t_dbuf  = bench_median_us(20, trials, fn_dbuf);
    auto t_drand = bench_median_us(20, trials, fn_derand);
    auto t_conv  = bench_median_us(20, trials, fn_conv);
    auto t_chi   = bench_median_us(20, trials, fn_chi_send);

    std::printf("=== rcot_recv_next (OT-sender role, computes u + v) ===\n");
    report("sfvole_send",  t_send,  true);
    report("d_buf XOR",    t_dbuf,  true);
    report("Conv",         t_conv,  true);
    report("chi_fold",     t_chi,   true);
    double recv_kernel = t_send + t_dbuf + t_conv;
    double recv_kernel_mal = recv_kernel + t_chi;
    std::printf("---\nkernel total (semihon) %10.2f us  (%6.3f ns/OT)\n",
                recv_kernel, recv_kernel * 1000.0 / chunk_OTs);
    std::printf("kernel total (malicious) %10.2f us  (%6.3f ns/OT)\n\n",
                recv_kernel_mal, recv_kernel_mal * 1000.0 / chunk_OTs);

    std::printf("=== rcot_send_next (OT-receiver role, computes w) ===\n");
    report("sfvole_recv",  t_recv,  true);
    report("apply_derand", t_drand, true);
    report("Conv",         t_conv,  true);
    report("chi_fold",     t_chi,   true);
    double send_kernel = t_recv + t_drand + t_conv;
    double send_kernel_mal = send_kernel + t_chi;
    std::printf("---\nkernel total (semihon) %10.2f us  (%6.3f ns/OT)\n",
                send_kernel, send_kernel * 1000.0 / chunk_OTs);
    std::printf("kernel total (malicious) %10.2f us  (%6.3f ns/OT)\n\n",
                send_kernel_mal, send_kernel_mal * 1000.0 / chunk_OTs);

    std::printf("# Compare these to test_softspoken<8> RCOT throughput:\n");
    std::printf("#   30.1 MOTps semi  → 33.2 ns/OT e2e (Apple M, post-butterfly).\n");
    std::printf("# IO/sync overhead = e2e ns/OT - kernel ns/OT.\n");
    return 0;
}
