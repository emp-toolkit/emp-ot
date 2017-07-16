#include "emp-ot"
#include <emp-tool>
#include <iostream>
#include "test/test.h"
using namespace std;

int main(int argc, char** argv) {
	int port, party, length = 1<<22;
	parse_party_and_port(argv, 2, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr:SERVER_IP, port);
	cout <<"COOT\t"<<10000.0/test_ot<NetIO, OTCO>(io, party, 10000)*1e6<<" OTps"<<endl;
	cout <<"Malicious OT Extension\t"<<double(length)/test_ot<NetIO, MOTExtension>(io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Malicious ROT Extension\t"<<double(length)/test_rot<NetIO, MOTExtension>(io, party, length)*1e6<<" OTps"<<endl;
	delete io;
}
