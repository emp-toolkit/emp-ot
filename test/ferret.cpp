#include "emp-ot/emp-ot.h"
#include "test/test.h"
using namespace std;

int port, party;
const static int threads = 1;

void test_ferret(int party, NetIO *ios[threads], int64_t num_ot) {
	auto start = clock_start();
	IOChannel* iochans[threads];
	for (int i = 0; i < threads; ++i) iochans[i] = ios[i];
	FerretCOT * ferretcot = new FerretCOT(party, threads, iochans, true, true, ferret_b13);
	double timeused = time_from(start);
	std::cout << party << "\tsetup\t" << timeused/1000 << "ms" << std::endl;

	// RCOT
	// The RCOTs will be generated at internal memory, and copied to user buffer
	int64_t num = 1 << num_ot;
	cout <<"Active FERRET RCOT\t"<<double(num)/test_rcot<FerretCOT>(ferretcot, ios[0], party, num, false)*1e6<<" OTps"<<endl;

	// RCOT inplace
	// The RCOTs will be generated at user buffer
	// Get the buffer size needed by calling byte_memory_need_inplace()
	uint64_t batch_size = ferretcot->ot_limit;
	cout <<"Active FERRET RCOT inplace\t"<<double(batch_size)/test_rcot<FerretCOT>(ferretcot, ios[0], party, batch_size, true)*1e6<<" OTps"<<endl;
	delete ferretcot;
}

int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	NetIO* ios[threads];
	// NetIO opens (port, port+1) per instance, so each thread's pair must be
	// 2 ports apart to avoid collisions.
	for(int i = 0; i < threads; ++i)
		ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port + 2*i);

	int64_t length = 24;
	if (argc > 3)
		length = atoi(argv[3]);
	if(length > 30) {
		cout <<"Large test size! comment me if you want to run this size\n";
		exit(1);
	}
		
	test_ferret(party, ios, length);

	for(int i = 0; i < threads; ++i)
		delete ios[i];
}
