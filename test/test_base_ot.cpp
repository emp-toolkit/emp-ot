// Base-OT correctness test. Sweeps the base-OT protocols CO / PVW / CSW /
// PVWKyber and, for each, runs the protocol and asserts the receiver's
// outputs via check_ot (which calls error() on mismatch). Correctness-only;
// throughput lives in bench/bench_base_ot.cpp. Two-party via the `run` script
// (loopback 127.0.0.1).
#include "test/test.h"
using namespace std;

// Per-protocol correctness check via the assert-only check_ot helper.
template <typename T>
void run_one(const char *name, T *ot, NetIO *io, int party, int64_t length) {
	cout << name << "\t";
	check_ot<T>(ot, io, party, length);
}

int main(int argc, char **argv) {
	int port, party;
	party = parse_party(argv);
	port = peer_port();
	auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

	// Base OTs are the security-parameter-fixed bootstrap (128 of them);
	// keep the test at that natural size — small and fast in CI regardless
	// of NDEBUG.
	constexpr int64_t length = 128;
	cout << (party == ALICE ? "Alice" : "Bob")
	     << " — verifying " << length << " base OTs:\n";

	{
		CO co(io.get());
		run_one("CO", &co, io.get(), party, length);
	}
	{
		PVW pvw(io.get());
		run_one("PVW", &pvw, io.get(), party, length);
	}
	{
		// CSW / PVWKy take a sid via set_sid(); without it they default to
		// zero_block. The test sets a deterministic sid so the cross-party
		// transcripts match exactly.
		block sid = makeBlock(0xCAFEBABE12345678ULL, 0xDEADBEEFFACEFEEDULL);
		CSW csw(io.get());
		csw.set_sid(sid);
		run_one("CSW", &csw, io.get(), party, length);
	}
	{
		block sid = makeBlock(0xCAFEBABE12345678ULL, 0x0BADC0DE0DEFACE0ULL);
		PVWKyber pvw_kyber(io.get());
		pvw_kyber.set_sid(sid);
		run_one("PVWKy", &pvw_kyber, io.get(), party, length);
	}
	cout << "\n";

	return 0;
}
