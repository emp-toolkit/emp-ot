#include "emp-ot/emp-ot.h"
#include "emp-tool/emp-tool.h"

using namespace emp;
using namespace std;

int party, port;

// Oracle check for an f2k VOLE triple: BOB ships its delta and the y (= mac)
// blocks; ALICE re-derives gfmul(delta, x) ^ k and compares against y.
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

// CI uses a smaller Ferret parameter set and few iterations so the suite
// finishes fast regardless of build mode.
static constexpr auto kSvoleParam   = tuning::ferret_b11;
static constexpr int  kOneshotIters = 2;

// Streaming-path exercise: begin -> many next -> end.
// Walks chunk-by-chunk through ~one round of outputs, verifying each.
void test_streaming(NetIO *io, int svole_party) {
  F2kVOLE<AuthValueF2k> vtriple(svole_party, io,
                                /*malicious=*/true, kSvoleParam);
  const block Delta = (svole_party == BOB) ? vtriple.delta() : zero_block;

  const int64_t chunk = vtriple.chunk_size();
  const int64_t per_round = vtriple.chunk_aligned_buf_sz();
  std::vector<AuthValueF2k> buf(chunk);
  std::vector<block> buf_x(chunk), buf_yz(chunk);

  // Two rounds via the streaming API. setup_done flips inside the first
  // begin (lazy bootstrap).
  vtriple.begin();

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
  F2kVOLE<AuthValueF2k> vtriple(svole_party, io,
                                /*malicious=*/true, kSvoleParam);
  const block Delta = (svole_party == BOB) ? vtriple.delta() : zero_block;

  const int64_t per_round = vtriple.chunk_aligned_buf_sz();
  std::vector<AuthValueF2k> buf(per_round);
  std::vector<block> buf_x(per_round), buf_yz(per_round);

  for (int i = 0; i < kOneshotIters; ++i) {
    vtriple.run(buf.data(), per_round);
    for (int64_t k = 0; k < per_round; ++k) {
      buf_x[k]  = buf[k].val;
      buf_yz[k] = buf[k].mac;
    }
    check_triple(Delta, buf_x.data(), buf_yz.data(), per_round, io);
  }
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
