#include "test/test.h"
#include <iomanip>
using namespace std;

// Per-protocol benchmark line: "<name>: <time> us  from sender=<B>  from receiver=<B>".
// Both numbers are sent data — bytes that travelled over the wire — labelled
// by which role emitted them. Both parties print the same numbers (each
// resolves "its sent / its recv" against its role).
template <typename T>
void run_one(const char *name, T *ot, NetIO *io, int party, int64_t length) {
	uint64_t sent = 0, recv = 0;
	double t = test_ot<T>(ot, io, party, length, &sent, &recv);
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
	parse_party_and_port(argv, &party, &port);
	NetIO *io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

	constexpr int64_t length = 128;
	cout << (party == ALICE ? "Alice" : "Bob")
	     << " — " << length << " base OTs:\n";

	{
		OTNP np(io);
		run_one("NP", &np, io, party, length);
	}
	{
		OTCO co(io);
		run_one("CO", &co, io, party, length);
	}
	{
		OTPVW pvw(io);
		run_one("PVW", &pvw, io, party, length);
	}
	{
		// CSW needs a session id matched across parties. Deterministic
		// for the test; in production derive from a fresh nonce.
		block sid = makeBlock(0xCAFEBABE12345678ULL, 0xDEADBEEFFACEFEEDULL);
		OTCSW csw(io, sid);
		run_one("CSW", &csw, io, party, length);
	}
	{
		// PVW-Kyber: post-quantum base OT (Module-LWE / ML-KEM-512).
		// Same sid convention as CSW.
		block sid = makeBlock(0xCAFEBABE12345678ULL, 0x0BADC0DE0DEFACE0ULL);
		OTPVWKyber pvw_kyber(io, sid);
		run_one("PVWKy", &pvw_kyber, io, party, length);
	}

	delete io;
	return 0;
}
