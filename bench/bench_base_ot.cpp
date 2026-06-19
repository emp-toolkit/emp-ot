// Base-OT throughput bench. Sweeps the base-OT protocols CO / PVW / CSW /
// PVWKyber and, for each, reports one line: "<name>: <time> us  from
// sender=<B>  from receiver=<B>". Both numbers are sent data — bytes that
// travelled over the wire — labelled by which role emitted them. Both parties
// print the same numbers (each resolves "its sent / its recv" against its
// role). Timing-only; correctness lives in test/test_base_ot.cpp. Two-party
// via the `run` script (loopback 127.0.0.1).
#include "bench/bench.h"
#include <iomanip>
using namespace std;

// Per-protocol benchmark line via the timing-only time_ot helper.
template <typename T>
void run_one(const char *name, T *ot, NetIO *io, int party, int64_t length) {
	uint64_t sent = 0, recv = 0;
	double t = time_ot<T>(ot, io, party, length, &sent, &recv);
	uint64_t from_sender = (party == ALICE) ? sent : recv;
	uint64_t from_recv   = (party == ALICE) ? recv : sent;
	cout << left << setw(6) << name
	     << " " << right << setw(8) << (long long)t << " us"
	     << "  from sender=" << setw(6) << from_sender << " B"
	     << "  from receiver=" << setw(6) << from_recv << " B"
	     << "\n";
}

int main(int argc, char **argv) {
	int port, party;
	party = parse_party(argv);
	port = peer_port();
	auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

	// Base OTs are the security-parameter-fixed bootstrap (128 of them),
	// so the bench length is the same in debug and release builds.
	constexpr int64_t length = 128;
	cout << (party == ALICE ? "Alice" : "Bob")
	     << " — " << length << " base OTs:\n";

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
		// zero_block. The bench sets a deterministic test sid so cross-party
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

	return 0;
}
