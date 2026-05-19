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

void check_triple(const block delta,
                  const block *x,
                  const block *y,
                  int64_t size,
                  NetIO *io) {
  if (party == BOB) {
    io->send_data(&delta, sizeof(block));
    io->send_data(y, size * sizeof(block));
    io->flush();
  } else {
    block delta_;
    block *k = new block[size];
    io->recv_data(&delta_, sizeof(block));
    io->recv_data(k, size * sizeof(block));
    for (int64_t i = 0; i < size; ++i) {
      block tmp;
      gfmul(delta_, x[i], &tmp);
      tmp = tmp ^ k[i];
      if ((memcmp(&tmp, &y[i], sizeof(block))) != 0) {
        std::cout << "triple error at index: " << i << std::endl;
        abort();
      }
    }
    delete[] k;
  }
}

// Debug builds use a smaller Ferret parameter set so the suite
// finishes in a reasonable CI window. Release-mode keeps the default
// (b13) for stress coverage of the largest parameter point.
#ifdef NDEBUG
static constexpr auto kSvoleParam   = tuning::ferret_b13;
static constexpr int  kOneshotIters = 8;
#else
static constexpr auto kSvoleParam   = tuning::ferret_b11;
static constexpr int  kOneshotIters = 2;
#endif

// Streaming-path exercise: begin → many next → end.
// Walks chunk-by-chunk through ~one round of outputs, verifying each.
void test_streaming(NetIO *io, int svole_party) {
  F2kVOLE<AuthValueF2k, NetIO> vtriple(svole_party, io,
                                       /*malicious=*/true, kSvoleParam);
  const block Delta = (svole_party == BOB) ? vtriple.delta() : zero_block;

  const int64_t chunk = vtriple.chunk_size();
  const int64_t per_round = vtriple.chunk_aligned_buf_sz();
  std::vector<AuthValueF2k> buf(chunk);
  std::vector<block> buf_x(chunk), buf_yz(chunk);

  // Two rounds via the streaming API. setup_done flips inside the first
  // begin (lazy bootstrap).
  auto t0 = clock_start();
  vtriple.begin();
  std::cout << "setup+begin " << time_from(t0) / 1000 << " ms" << std::endl;

  const int64_t total_chunks = (per_round / chunk) * 2;
  for (int64_t i = 0; i < total_chunks; ++i) {
    vtriple.next(buf.data());
    for (int64_t k = 0; k < chunk; ++k) {
      buf_x[k]  = buf[k].val;
      buf_yz[k] = buf[k].mac;
    }
    check_triple(Delta, buf_x.data(), buf_yz.data(), chunk, io);
  }
  vtriple.end();
}

// One-shot path: run(out, num) with chunk-aligned num. ram-zk uses
// the same shape with `num = chunk_aligned_buf_sz()`.
void test_oneshot(NetIO *io, int svole_party) {
  F2kVOLE<AuthValueF2k, NetIO> vtriple(svole_party, io,
                                       /*malicious=*/true, kSvoleParam);
  const block Delta = (svole_party == BOB) ? vtriple.delta() : zero_block;

  const int64_t per_round = vtriple.chunk_aligned_buf_sz();
  std::vector<AuthValueF2k> buf(per_round);
  std::vector<block> buf_x(per_round), buf_yz(per_round);

  for (int i = 0; i < kOneshotIters; ++i) {
    auto start = clock_start();
    vtriple.run(buf.data(), per_round);
    std::cout << "extend " << time_from(start) / 1000 << " ms" << std::endl;
    for (int64_t k = 0; k < per_round; ++k) {
      buf_x[k]  = buf[k].val;
      buf_yz[k] = buf[k].mac;
    }
    check_triple(Delta, buf_x.data(), buf_yz.data(), per_round, io);
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
  test_streaming(io, party);

  std::cout << std::endl
            << "------------ VOLE f2k (one-shot) ------------" << std::endl
            << std::endl;
  test_oneshot(io, party);

  delete io;
  return 0;
}
