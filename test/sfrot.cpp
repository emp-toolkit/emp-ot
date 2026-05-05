#include "test/test.h"
using namespace std;

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

	// Caller-supplied sid: deterministic for the test so both sides agree.
	// In production, derive from a fresh nonce exchanged at session start.
	block sid = makeBlock(0xCAFEBABE12345678ULL, 0xDEADBEEFFACEFEEDULL);

	OTSFROT * sfrot = new OTSFROT(io, sid);
	cout << "128 SFROT base OTs:\t"
	     << test_ot<OTSFROT>(sfrot, io, party, 128) << " us" << endl;
	delete sfrot;

	OTCO * co = new OTCO(io);
	cout << "128 CO OTs:\t\t"
	     << test_ot<OTCO>(co, io, party, 128) << " us" << endl;
	delete co;

	OTPVW * pvw = new OTPVW(io);
	cout << "128 PVW OTs:\t\t"
	     << test_ot<OTPVW>(pvw, io, party, 128) << " us" << endl;
	delete pvw;

	OTNP * np = new OTNP(io);
	cout << "128 NPOTs:\t\t"
	     << test_ot<OTNP>(np, io, party, 128) << " us" << endl;
	delete np;

	delete io;
	return 0;
}
