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
// ALICE ships Δ and her mac_i; BOB verifies K_i locally — same shape as
// test_f2k_vole (the Δ-holder ships, the other party checks).
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
// NDEBUG. The default-point stress coverage lives in bench_fp_vole.
static constexpr auto kSvoleParam   = tuning::ferret_b9;
static constexpr int  kOneshotIters = 2;

// Differential check for the carrier's lazy reductions: MacSum (the gadget's
// per-tree Σ mac) and accumulate_VW (Σ chi·mac) reduce once at the end and
// must return the element the add_mod / mult_mod chains return. The sizes run
// to the largest shipped tree (2^13 leaves), and the second pass sets every
// operand to p - 1, the largest term either sum can take.
bool test_lazy_reductions() {
  const block seed = makeBlock(0x6670206c617a7972ULL,
                               0x656475637469306eULL);
  PRG prg(&seed);
  constexpr int64_t sizes[] = {0, 1, 2, 3, 4, 5, 7, 16, 127, 128, 1024,
                               4096, 8192};
  for (int pass = 0; pass < 2; ++pass) {
    for (int64_t size : sizes) {
      std::vector<uint64_t> chi(size);
      std::vector<AuthValueFp> leaves(size);
      for (int64_t i = 0; i < size; ++i) {
        uint64_t r[2];
        prg.random_data_unaligned(r, sizeof(r));
        chi[i] = pass ? PR - 1 : mod(r[0]);
        leaves[i].mac = pass ? PR - 1 : mod(r[1]);
      }
      uint64_t sum = 0, vw = 0;
      AuthValueFp::MacSum lazy_sum;
      for (int64_t i = 0; i < size; ++i) {
        sum = add_mod(sum, leaves[i].mac);
        vw = add_mod(vw, mult_mod(chi[i], leaves[i].mac));
        lazy_sum.add(leaves[i].mac);
      }
      uint64_t lazy_vw = PR;   // not canonical: must be overwritten
      AuthValueFp::accumulate_VW(lazy_vw, chi.data(), leaves.data(), size);
      if (lazy_sum.value() != sum || lazy_vw != vw) {
        std::cerr << "AuthValueFp lazy reduction mismatch at size " << size
                  << (pass ? " (operands p - 1)" : "") << std::endl;
        return false;
      }
    }
  }
  return true;
}

// Streaming-path exercise: begin → many next → end.
// Walks chunk-by-chunk through two rounds of outputs, verifying each.
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

// The public LPN matrix is seeded with RO(domain, sid) of the sid set
// before bootstrap (svole.h).
static void check_lpn_seed(block key, const char *domain, block sid) {
  const block want = svole_lpn_seed(domain, sid);
  if (!cmpBlock(&key, &want, 1)) {
    std::cout << "LPN seed is not RO(domain, sid)" << std::endl;
    abort();
  }
}

// One-shot path: run(out, num) with chunk-aligned num. Runs under a
// non-default session id.
void test_oneshot(NetIO *io, int svole_party) {
  FpVOLE<AuthValueFp> vtriple(svole_party, io,
                              /*malicious=*/true, kSvoleParam);
  const block sid = makeBlock(0x6670766f6c652d6fULL, 0x6e6573686f742d73ULL);
  vtriple.set_sid(SessionID(sid));
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
  check_lpn_seed(vtriple.lpn_->prg_key(), AuthValueFp::kLpnSeedDomain, sid);
}

// Check the first n outputs of buf with the triple oracle.
static void check_outputs(uint64_t delta, const std::vector<AuthValueFp> &buf,
                          int64_t n, NetIO *io) {
  std::vector<uint64_t> val(n), mac(n);
  for (int64_t k = 0; k < n; ++k) {
    val[k] = buf[k].val;
    mac[k] = buf[k].mac;
  }
  check_triple(delta, val.data(), mac.data(), n, io);
}

// Semi-honest one-shot runs at lengths that are not whole chunks, then a
// malicious session whose next_n counts cut across chunk boundaries.
void test_short_sessions(NetIO *io, int svole_party) {
  {
    FpVOLE<AuthValueFp> vtriple(svole_party, io,
                                /*malicious=*/false, kSvoleParam);
    const uint64_t Delta = svole_party == ALICE ? vtriple.delta() : 0;
    const int64_t chunk = vtriple.chunk_size();
    for (int64_t n : {int64_t{1}, int64_t{1000}, chunk + 3}) {
      std::vector<AuthValueFp> buf(n);
      vtriple.run(buf.data(), n);
      check_outputs(Delta, buf, n, io);
    }
  }
  {
    FpVOLE<AuthValueFp> vtriple(svole_party, io,
                                /*malicious=*/true, kSvoleParam);
    const uint64_t Delta = svole_party == ALICE ? vtriple.delta() : 0;
    const int64_t chunk = vtriple.chunk_size();
    vtriple.begin();
    for (int64_t n : {int64_t{5}, chunk + 7, int64_t{3}}) {
      std::vector<AuthValueFp> buf(n);
      vtriple.next_n(buf.data(), n);
      check_outputs(Delta, buf, n, io);
    }
    vtriple.end();
  }
}

int main(int argc, char **argv) {
  if (!test_lazy_reductions()) return 1;

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

  std::cout << std::endl
            << "------------ VOLE Fp (short sessions) ------------" << std::endl
            << std::endl;
  test_short_sessions(io.get(), party);

  return 0;
}
