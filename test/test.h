#include "emp-ot"
#include <emp-tool>

template<typename IO, template<typename>class T>
double test_ot(IO * io, int party, int length) {
	block *b0 = new block[length], *b1 = new block[length], *r = new block[length];
	PRG prg(fix_key);
	prg.random_block(b0, length);
	prg.random_block(b1, length);
	bool *b = new bool[length];
	prg.random_bool(b, length);

	io->sync();
	auto start = clock_start();
	T<IO> * ot = new T<IO>(io);
	if (party == ALICE) {
		ot->send(b0, b1, length);
	} else {
		ot->recv(r, b, length);
	}
	io->flush();
	long long t = time_from(start);
	if(party == BOB) for(int i = 0; i < length; ++i) {
		if (b[i]) assert(block_cmp(&r[i], &b1[i], 1));
		else assert(block_cmp(&r[i], &b0[i], 1));
	}
	delete ot;
	delete[] b0;
	delete[] b1;
	delete[] r;
	delete[] b;
	return t;
}
template<typename IO, template<typename>class T>
double test_cot(NetIO * io, int party, int length) {
	block *b0 = new block[length], *r = new block[length];
	bool *b = new bool[length];
	block delta;
	PRG prg(fix_key);
	prg.random_block(&delta, 1);
	prg.random_bool(b, length);
	
	io->sync();
	auto start = clock_start();
	T<IO>* ot = new T<IO>(io);
	if (party == ALICE) {
		ot->send_cot(b0, delta, length);
	} else {
		ot->recv_cot(r, b, length);
	}
	io->flush();
	long long t = time_from(start);
	if(party == ALICE)
			io->send_block(b0, length);
	else if(party == BOB)  {
		io->recv_block(b0, length);
		for(int i = 0; i < length; ++i) {
			block b1 = xorBlocks(b0[i], delta); 
			if (b[i]) {
				if(!block_cmp(&r[i], &b1, 1))
					error("COT failed!");
			} else {
				if(!block_cmp(&r[i], &b0[i], 1))
					error("COT failed!");
			}
		}
	}
	io->flush();
	delete ot;
	delete[] b0;
	delete[] r;
	delete[] b;
	return t;
}

template<typename IO, template<typename>class T>
double test_rot(IO * io, int party, int length) {
	block *b0 = new block[length], *r = new block[length];
	block *b1 = new block[length];
	bool *b = new bool[length];
	PRG prg;
	prg.random_bool(b, length);
	
	io->sync();
	auto start = clock_start();
	T<IO>* ot = new T<IO>(io);
	if (party == ALICE) {
		ot->send_rot(b0, b1, length);
	} else {
		ot->recv_rot(r, b, length);
	}
	io->flush();
	long long t = time_from(start);
	if(party == ALICE) {
			io->send_block(b0, length);
			io->send_block(b1, length);
	} else if(party == BOB)  {
			io->recv_block(b0, length);
			io->recv_block(b1, length);
		for(int i = 0; i < length; ++i) {
			if (b[i]) assert(block_cmp(&r[i], &b1[i], 1));
			else assert(block_cmp(&r[i], &b0[i], 1));
		}
	}
	io->flush();
	delete ot;
	delete[] b0;
	delete[] b1;
	delete[] r;
	delete[] b;
	return t;
}
