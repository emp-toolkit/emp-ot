#include "emp-ot/emp-ot.h"
#include "emp-tool/emp-tool.h"
#if defined(__linux__)
#include <sys/time.h>
#include <sys/resource.h>
#elif defined(__APPLE__)
#include <unistd.h>
#include <sys/resource.h>
#include <mach/mach.h>
#endif

using namespace emp;
using namespace std;

int party, port;

// Release-mode keeps the default (b13) for stress coverage of the largest
// parameter point.
static constexpr auto kSvoleParam   = tuning::ferret_b13;
static constexpr int  kOneshotIters = 8;

// Streaming-path timing: begin -> many next -> end.
// Reports setup+begin and walks chunk-by-chunk through two rounds of outputs.
void bench_streaming(NetIO *io, int svole_party) {
  F2kVOLE<AuthValueF2k> vtriple(svole_party, io,
                                /*malicious=*/true, kSvoleParam);

  const int64_t chunk = vtriple.chunk_size();
  const int64_t per_round = vtriple.chunk_aligned_buf_sz();
  std::vector<AuthValueF2k> buf(chunk);

  // Two rounds via the streaming API. setup_done flips inside the first
  // begin (lazy bootstrap).
  auto t0 = clock_start();
  vtriple.begin();
  std::cout << "setup+begin " << time_from(t0) / 1000 << " ms" << std::endl;

  const int64_t total_chunks = (per_round / chunk) * 2;
  for (int64_t i = 0; i < total_chunks; ++i) {
    vtriple.next(buf.data());
  }
  vtriple.end();
}

// One-shot path: run(out, num) with chunk-aligned num. ram-zk uses
// the same shape with `num = chunk_aligned_buf_sz()`.
void bench_oneshot(NetIO *io, int svole_party) {
  F2kVOLE<AuthValueF2k> vtriple(svole_party, io,
                                /*malicious=*/true, kSvoleParam);

  const int64_t per_round = vtriple.chunk_aligned_buf_sz();
  std::vector<AuthValueF2k> buf(per_round);

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

  NetIO *io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

  std::cout << std::endl
            << "------------ VOLE f2k (streaming) ------------" << std::endl
            << std::endl;
  bench_streaming(io, party);

  std::cout << std::endl
            << "------------ VOLE f2k (one-shot) ------------" << std::endl
            << std::endl;
  bench_oneshot(io, party);

  delete io;
  return 0;
}
