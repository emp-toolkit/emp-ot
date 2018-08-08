// lattice.cpp contains tests for the implementation of the
// PVW08 lattice-based oblivious transfer protocol
#include "test/test.h"
#include "emp-ot/lattice.h"
#include <cmath>
#include <iostream>
#ifndef EMP_USE_RANDOM_DEVICE
#define EMP_USE_RANDOM_DEVICE
#endif
using namespace std;

int main(int argc, char **argv) {
	constexpr int N_BITS = 128;
	static_assert(N_BITS <= 128 and N_BITS >= 1,
	              "Bits per OT must be between 1 and 128 (inclusive).");
	int N_TESTS = 128;
	int port, party;
	parse_party_and_port(argv, 2, &party, &port);
	NetIO *io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

	auto time_in_usec = test_bit_ot<NetIO, OTLattice, N_BITS>(io, party, N_TESTS);
	if (party == ALICE) {
		cout << "Lattice OT \t" << double(N_TESTS) * 1e6 / time_in_usec << " OTps"
		     << endl;
	}
	delete io;
}
