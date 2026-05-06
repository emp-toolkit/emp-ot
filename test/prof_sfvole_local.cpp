// Tight-loop driver for `sample` / Instruments profiling of the
// SoftSpoken sfvole inner loop. Runs the chosen kernel for the
// configured wall-clock time, no network / session plumbing.
//
// Usage:
//   ./build/test/test_prof_sfvole_local <secs> [send|recv|aes_only]
//   sample $(pgrep test_prof_sfvole_local) <secs-1> -mayDie >/tmp/profile.txt

#include <emp-tool/emp-tool.h>
#include "emp-ot/softspoken/softspoken_ot.h"
#include "emp-ot/softspoken/sfvole_butterfly.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace emp;

int main(int argc, char** argv) {
    constexpr int k = 8;
    constexpr int n = SoftSpokenOT<k>::n;
    constexpr int Q = 1 << k;
    const int64_t bs = SoftSpokenOT<k>::kChunkBlocks;

#ifdef NDEBUG
    constexpr double default_secs = 10.0;
#else
    constexpr double default_secs = 1.0;
#endif
    double secs = (argc >= 2) ? atof(argv[1]) : default_secs;
    std::string mode = (argc >= 3) ? argv[2] : "recv";

    PRG prg(fix_key);
    std::vector<block> leaves((size_t)n * Q);
    prg.random_block(leaves.data(), n * Q);
    std::vector<int> alphas((size_t)n);
    for (int i = 0; i < n; ++i) alphas[i] = (i * 17) & (Q - 1);

    std::vector<block> planes_chunk((size_t)n * k * bs);
    std::vector<block> u_chunk((size_t)bs);
    std::vector<block> u_temp((size_t)bs);

    std::fprintf(stderr,
                 "prof_sfvole_local: mode=%s k=%d Q=%d n=%d bs=%lld secs=%.1f\n",
                 mode.c_str(), k, Q, n, (long long)bs, secs);
    std::fprintf(stderr, "pid=%d  attach with: sample %d %.0f -mayDie\n",
                 (int)getpid(), (int)getpid(), secs - 1.0);
    std::fprintf(stderr, "sleeping 0.5s before main loop so sampler can attach...\n");

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // For aes_only mode: pre-fold session into per-leaf tweaks once;
    // then in the loop generate AES output directly into planes_chunk
    // via the same aes_T_blocks helper that sfvole_butterfly uses, but
    // without the halve. Lets us decompose sfvole into "AES gen" vs
    // "everything else (halve + scratch traffic)".
    alignas(16) block tweaks[Q];
    {
        const block session_xor = makeBlock(0LL, 0xc0ffeeLL);
        for (int x = 0; x < Q; ++x) tweaks[x] = leaves[x] ^ session_xor;
    }
    AES_KEY fixed_K;
    AES_set_encrypt_key(_mm_loadu_si128((const __m128i*)fix_key), &fixed_K);

    auto t0 = std::chrono::steady_clock::now();
    int64_t chunks = 0;
    while (true) {
        if (mode == "recv") {
            for (int i = 0; i < n; ++i) {
                block* w_i = planes_chunk.data() + (size_t)i * k * bs;
                softspoken::sfvole_receiver_compute_chunk<k>(
                    alphas[i], leaves.data() + (size_t)i * Q,
                    /*session=*/0xc0ffeeULL, /*b0=*/0, bs, w_i);
            }
        } else if (mode == "send") {
            for (int i = 0; i < n; ++i) {
                block* v_i = planes_chunk.data() + (size_t)i * k * bs;
                block* u_dst = (i == 0) ? u_chunk.data() : u_temp.data();
                softspoken::sfvole_sender_compute_chunk<k>(
                    leaves.data() + (size_t)i * Q,
                    /*session=*/0xc0ffeeULL, /*b0=*/0, bs, u_dst, v_i);
            }
        } else if (mode == "aes_only") {
            // Generate the same total amount of AES output as sfvole but
            // skip the butterfly halve and v_b accumulation. Same loop
            // structure (n × Q × bs blocks) so the comparison is fair.
            constexpr int T = 8;
            for (int i = 0; i < n; ++i) {
                block* dst = planes_chunk.data() + (size_t)i * k * bs;
                for (int64_t t0_inner = 0; t0_inner < bs; t0_inner += T) {
                    for (int x = 0; x < Q; ++x) {
                        // Write to a different stride so we touch L1
                        // like the real kernel does. Modulo mapping:
                        // planes_chunk[i*k*bs + (x % k)*bs + t0_inner + jj].
                        block* row = dst + (size_t)(x & (k - 1)) * bs + t0_inner;
                        softspoken::bfly_detail::aes_T_blocks_to<T>(
                            row, t0_inner, &fixed_K, tweaks[x]);
                    }
                }
            }
        } else {
            std::fprintf(stderr, "unknown mode: %s\n", mode.c_str());
            return 1;
        }
        ++chunks;
        double elapsed = std::chrono::duration<double>(
                            std::chrono::steady_clock::now() - t0).count();
        if (elapsed >= secs) {
            std::fprintf(stderr,
                         "%lld chunks in %.3fs -> %.2f us/chunk (n=%d sub-VOLEs each)\n",
                         (long long)chunks, elapsed, elapsed * 1e6 / chunks, n);
            break;
        }
    }

    return 0;
}
