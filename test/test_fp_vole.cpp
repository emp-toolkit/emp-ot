#include "emp-ot/emp-ot.h"
#include "emp-ot/svole/fp_vole.h"
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

void test_streaming(NetIO *io, int svole_party) {
  FpVOLE<AuthValueFp, NetIO> vtriple(svole_party, io);
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
  std::vector<uint64_t> buf_val(chunk), buf_mac(chunk);

  auto t0 = clock_start();
  vtriple.begin();
  std::cout << "setup+begin " << time_from(t0) / 1000 << " ms" << std::endl;

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

void test_oneshot(NetIO *io, int svole_party) {
  FpVOLE<AuthValueFp, NetIO> vtriple(svole_party, io);
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
  std::vector<uint64_t> buf_val(per_round), buf_mac(per_round);

  for (int i = 0; i < 8; ++i) {
    auto start = clock_start();
    vtriple.run(buf.data(), per_round);
    std::cout << "extend " << time_from(start) / 1000 << " ms" << std::endl;
    for (int64_t k = 0; k < per_round; ++k) {
      buf_val[k] = buf[k].val;
      buf_mac[k] = buf[k].mac;
    }
    check_triple(Delta, buf_val.data(), buf_mac.data(), per_round, io);
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
            << "------------ VOLE Fp (streaming) ------------" << std::endl
            << std::endl;
  test_streaming(io, party);

  std::cout << std::endl
            << "------------ VOLE Fp (one-shot) ------------" << std::endl
            << std::endl;
  test_oneshot(io, party);

  delete io;
  return 0;
}
