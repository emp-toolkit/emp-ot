#include "emp-ot/emp-ot.h"
#include "emp-ot/svole/fp_vole.h"
#include "emp-tool/emp-tool.h"

// Correctness test for VOLE over F_p (Mersenne 2^61 - 1). Mirror of
// test_f2k_vole: drives the streaming (begin/next/end) and one-shot
// (run) paths and asserts every output via the authenticated-triple
// oracle below. No timing here -- throughput lives in bench_fp_vole.
// Includes emp-ot.h directly. A small fixed Ferret parameter set keeps
// CI fast regardless of NDEBUG.

using namespace emp;
using namespace std;

int party, port;

// Authenticated triple check for F_p (Mersenne 2^61 - 1):
//   ALICE has (Δ, mac_i); BOB has (val_i, K_i).
//   Invariant: K_i ≡ mac_i + Δ × val_i (mod p).
// BOB ships (Δ_alice received from ALICE, all K_i / val_i), ALICE
// verifies locally — same shape as test_f2k_vole.
void check_triple(uint64_t delta, const uint64_t *val, const uint64_t *mac,
                  int64_t size, NetIO *io) {
  if (party == ALICE) {
    io->send_data(&delta, sizeof(uint64_t));
    io->send_data(mac, size * sizeof(uint64_t));
    io->flush();
  } else {
    uint64_t delta_;
    std::vector<uint64_t> mac_alice(size);
    io->recv_data(&delta_, sizeof(uint64_t));
    io->recv_data(mac_alice.data(), size * sizeof(uint64_t));
    for (int64_t i = 0; i < size; ++i) {
      uint64_t tmp = mult_mod(delta_, val[i]);
      tmp = add_mod(tmp, mac_alice[i]);
      if (tmp != mac[i]) {
        std::cout << "triple error at index: " << i << " : "
                  << tmp << " vs " << mac[i] << std::endl;
        abort();
      }
    }
  }
}

// Small fixed parameter set so CI finishes quickly regardless of
// NDEBUG. The largest-point stress coverage lives in bench_fp_vole.
static constexpr auto kSvoleParam   = tuning::ferret_b11;
static constexpr int  kOneshotIters = 2;

// Streaming-path exercise: begin → many next → end.
// Walks chunk-by-chunk through ~one round of outputs, verifying each.
void test_streaming(NetIO *io, int svole_party) {
  FpVOLE<AuthValueFp> vtriple(svole_party, io,
                              /*malicious=*/true, kSvoleParam);
  uint64_t Delta = 0;
  if (svole_party == ALICE) Delta = vtriple.delta();

  const int64_t chunk = vtriple.chunk_size();
  const int64_t per_round = vtriple.chunk_aligned_buf_sz();
  std::vector<AuthValueFp> buf(chunk);
  std::vector<uint64_t> buf_val(chunk), buf_mac(chunk);

  vtriple.begin();

  const int64_t total_chunks = (per_round / chunk) * 2;
  for (int64_t i = 0; i < total_chunks; ++i) {
    vtriple.next(buf.data());
    for (int64_t k = 0; k < chunk; ++k) {
      buf_val[k] = buf[k].val;
      buf_mac[k] = buf[k].mac;
    }
    check_triple(Delta, buf_val.data(), buf_mac.data(), chunk, io);
  }
  vtriple.end();
}

// One-shot path: run(out, num) with chunk-aligned num.
void test_oneshot(NetIO *io, int svole_party) {
  FpVOLE<AuthValueFp> vtriple(svole_party, io,
                              /*malicious=*/true, kSvoleParam);
  uint64_t Delta = 0;
  if (svole_party == ALICE) Delta = vtriple.delta();

  const int64_t per_round = vtriple.chunk_aligned_buf_sz();
  std::vector<AuthValueFp> buf(per_round);
  std::vector<uint64_t> buf_val(per_round), buf_mac(per_round);

  for (int i = 0; i < kOneshotIters; ++i) {
    vtriple.run(buf.data(), per_round);
    for (int64_t k = 0; k < per_round; ++k) {
      buf_val[k] = buf[k].val;
      buf_mac[k] = buf[k].mac;
    }
    check_triple(Delta, buf_val.data(), buf_mac.data(), per_round, io);
  }
}

int main(int argc, char **argv) {
  party = parse_party(argv);
  port = peer_port();

  auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

  std::cout << std::endl
            << "------------ VOLE Fp (streaming) ------------" << std::endl
            << std::endl;
  test_streaming(io.get(), party);

  std::cout << std::endl
            << "------------ VOLE Fp (one-shot) ------------" << std::endl
            << std::endl;
  test_oneshot(io.get(), party);

  return 0;
}
