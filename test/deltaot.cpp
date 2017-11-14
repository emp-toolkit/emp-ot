#include <emp-tool/emp-tool.h>
#include "emp-ot/emp-ot.h"
#include <thread>
using namespace std;
using namespace emp;

int size = 1<<24;
bool * tmp = new bool[256];

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	block * t1 = new block[size];
	bool* bb = new bool[size];
	PRG prg;
	prg.random_bool(tmp, 256);
	block * pretable = DeltaOT::preTable(40);
	NetIO *io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);
	DeltaOT * abit = new DeltaOT(io, pretable, 40);
	prg.random_bool(bb, size);

	auto start = clock_start();
	if (party == ALICE) {
		abit->setup_send(tmp);
	} else {
		abit->setup_recv();
	}
	cout << "Setup : "<< time_from(start)<<endl;
	start = clock_start();

	if (party == ALICE) {
		abit->send(t1, size);
	} else {
		abit->recv(t1, bb, size);
	}
	cout <<"Delta OT\t"<<double(size)/time_from(start)*1e6<<" OTps"<<endl;

	block Delta, tmp;
	if (party == ALICE) {
		io->send_block(&(abit->Delta), 1);
		io->send_block(t1, size);
	} else {
		io->recv_block (&Delta, 1);
		for(int i = 0; i < size; ++i) {
			io->recv_block (&tmp, 1);
			if(bb[i])
				tmp = xorBlocks(tmp, Delta);
			if(memcmp(&t1[i], &tmp, 16)!=0) {
				error("Wrong Results\n");
			}
		}
	}
	return 0;
}
