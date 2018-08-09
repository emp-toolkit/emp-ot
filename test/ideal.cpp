#include "test/test.h"
#include <iostream>
using namespace std;

int main(int argc, char** argv) {
	int length = 1<<24, port, party;
	parse_party_and_port(argv, 2, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);
	//cout <<"NPOT\t"<<10000.0/test_ot<NetIO, OTNP>(io, party, 10000)*1e6<<" OTps"<<endl;

	// Test the ideal full trust model. More of an example of how tests can be written.
	cout <<"Ideal OT Extension\t"<<double(length)/test_ot<NetIO, OTIdeal>(io, party, length)*1e6<<" OTps"<<endl;
	
	
	delete io;
}

