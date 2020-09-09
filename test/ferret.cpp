#include "emp-ot/emp-ot.h"
using namespace std;

int port, party;
const static int threads = 5;

void test_ferret(int party, NetIO *ios[threads+1]) {
	auto start = clock_start();
	FerretCOT<NetIO, threads> * ferretcot = new FerretCOT<NetIO, threads>(party, ios, true);
	double timeused = time_from(start);
	std::cout << party << "\tsetup\t" << timeused/1000 << "ms" << std::endl;

	int num = 1 << 24;
	block *ot_data_alloc = new block[num];
	std::cout << "\ngenerating " << num << " COTs: " << std::endl;
	start = clock_start();
	ferretcot->rcot(ot_data_alloc, num);
	timeused = time_from(start);
	std::cout << party << "\tCOT\t" << timeused/1000 << "ms" << std::endl;
	delete[] ot_data_alloc;

	num = 3*ferretcot->ot_limit;
	uint64_t memory_len = ferretcot->byte_memory_need_inplace((uint64_t)num);
	ot_data_alloc = new block[memory_len];
	std::cout << "\ngenerating " << memory_len - ferretcot->n_pre << " COTs inplace: " << std::endl;
	start = clock_start();
	uint64_t ot_output_n = ferretcot->rcot_inplace(ot_data_alloc, memory_len);
	timeused = time_from(start);
	std::cout << party << "\t" << ot_output_n << " COT emplace\t" << timeused/1000 << "ms" << std::endl;
	delete[] ot_data_alloc;

	num = ferretcot->ot_limit;
	memory_len = ferretcot->byte_memory_need_inplace((uint64_t)num);
	ot_data_alloc = new block[memory_len];
	std::cout << "\nefficiency benchmark: " << std::endl;
	start = clock_start();
	ferretcot->rcot_inplace(ot_data_alloc, memory_len);
	timeused = time_from(start);
	std::cout << party << "\t[benchmark] time per COT element\t" << timeused*1000/ferretcot->ot_limit << "ns" << std::endl;
	delete[] ot_data_alloc;

	delete ferretcot;
}

int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	NetIO* ios[threads+1];
	for(int i = 0; i < threads+1; ++i)
		ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port);

	test_ferret(party, ios);

	for(int i = 0; i < threads+1; ++i)
		delete ios[i];
}
