#include <iostream>
#include "test/test.h"
using namespace std;

int main(int argc, char** argv) {
	int length = 1, port, party;
	parse_party_and_port(argv, 2, &party, &port);
	NetIO * io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

  cout << "Initialized IO!" << endl;
	// Test lattice oblivious transfer
	cout << "Lattice OT \t"
    << double(length) / test_bit_ot<NetIO, OTLattice>(io, party, length)*1e6
    << " OTps" << endl;
	delete io;
}
