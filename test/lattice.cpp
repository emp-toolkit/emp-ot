#include <iostream>
#include "test/test.h"
#ifndef EMP_USE_RANDOM_DEVICE
#define EMP_USE_RANDOM_DEVICE
#endif
using namespace std;

int main(int argc, char** argv) {
	int N_TESTS = 1000;
	int port, party;
	parse_party_and_port(argv, 2, &party, &port);
	NetIO * io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

	// Test lattice oblivious transfer
	cout << "Lattice OT \t"
	     << double(N_TESTS) / test_ot<NetIO, OTLattice>(io, party, N_TESTS)*1e6
	     << " OTps" << endl;
	delete io;
}
