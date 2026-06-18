#include "emp-ot/emp-ot.h"
#include "emp-ot/svole/fp_vole.h"
#include "emp-tool/emp-tool.h"
#include "bench/bench.h"
#if defined(__linux__)
#include <sys/time.h>
#include <sys/resource.h>
#elif defined(__APPLE__)
#include <unistd.h>
#include <sys/resource.h>
#include <mach/mach.h>
#endif

// Throughput bench for VOLE over F_p (Mersenne 2^61 - 1). Mirror of
// bench_f2k_vole: drives the streaming (begin/next/end) and one-shot
// (run) paths and reports per-phase wall time (ms) plus peak RSS. No
// correctness oracle here -- the authenticated-triple check lives in
// the matching test_fp_vole. Includes emp-ot.h directly.

using namespace emp;
using namespace std;

int party, port;

// Largest parameter point for stress / throughput coverage.
static constexpr auto kSvoleParam   = tuning::ferret_b13;
static constexpr int  kOneshotIters = 8;

void bench_streaming(NetIO *io, int svole_party) {
  FpVOLE<AuthValueFp> vtriple(svole_party, io,
                              /*malicious=*/true, kSvoleParam);
  uint64_t Delta = 0;
  if (svole_party == ALICE) {
    PRG prg;
    prg.random_data_unaligned(&Delta, sizeof(uint64_t));
    Delta = mod(Delta);
    if (Delta == 0) Delta = 1;
    vtriple.set_delta(Delta);
  }

  const int64_t chunk = vtriple.chunk_size();
  const int64_t per_round = vtriple.chunk_aligned_buf_sz();
  std::vector<AuthValueFp> buf(chunk);

  auto t0 = clock_start();
  vtriple.begin();
  std::cout << "setup+begin " << time_from(t0) / 1000 << " ms" << std::endl;

  const int64_t total_chunks = (per_round / chunk) * 2;
  for (int64_t i = 0; i < total_chunks; ++i) {
    vtriple.next(buf.data());
  }
  vtriple.end();
}

void bench_oneshot(NetIO *io, int svole_party) {
  FpVOLE<AuthValueFp> vtriple(svole_party, io,
                              /*malicious=*/true, kSvoleParam);
  uint64_t Delta = 0;
  if (svole_party == ALICE) {
    PRG prg;
    prg.random_data_unaligned(&Delta, sizeof(uint64_t));
    Delta = mod(Delta);
    if (Delta == 0) Delta = 1;
    vtriple.set_delta(Delta);
  }

  const int64_t per_round = vtriple.chunk_aligned_buf_sz();
  std::vector<AuthValueFp> buf(per_round);

  for (int i = 0; i < kOneshotIters; ++i) {
    auto start = clock_start();
    vtriple.run(buf.data(), per_round);
    std::cout << "extend " << time_from(start) / 1000 << " ms" << std::endl;
  }

#if defined(__linux__)
  struct rusage rusage;
  if (!getrusage(RUSAGE_SELF, &rusage))
    std::cout << "[Linux]Peak resident set size: " << (size_t)rusage.ru_maxrss
              << std::endl;
#elif defined(__APPLE__)
  struct mach_task_basic_info info;
  mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
  if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info,
                &count) == KERN_SUCCESS)
    std::cout << "[Mac]Peak resident set size: "
              << (size_t)info.resident_size_max << std::endl;
#endif
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);

  NetIO *io = new NetIO(party == ALICE ? nullptr : bench_peer_host(), port);

  std::cout << std::endl
            << "------------ VOLE Fp (streaming) ------------" << std::endl
            << std::endl;
  bench_streaming(io, party);

  std::cout << std::endl
            << "------------ VOLE Fp (one-shot) ------------" << std::endl
            << std::endl;
  bench_oneshot(io, party);

  delete io;
  return 0;
}
