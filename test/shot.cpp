//#include "emp-ot.h"
#include "emp-ot"
#include <emp-tool>
#include <iostream>
using namespace std;

template<typename T>
double test_ot(NetIO * io, int party, int length, T* ot = nullptr, int TIME = 10) {
	block *b0 = new block[length], *b1 = new block[length], *r = new block[length];
	PRG prg(fix_key);
	prg.random_block(b0, length);
	prg.random_block(b1, length);
	bool *b = new bool[length];
	for(int i = 0; i < length; ++i) {
		b[i] = (rand()%2)==1;
	}

	long long t1 = 0, t = 0;
	io->sync();
	for(int i = 0; i < TIME; ++i) {
		t1 = timeStamp();
		if (ot == nullptr)
			ot = new T(io);
		if (party == ALICE) {
			ot->send(b0, b1, length);
		} else {
			ot->recv(r, b, length);
		}
		t += timeStamp()-t1;
	}
	if(party == BOB) for(int i = 0; i < length; ++i) {
		if (b[i]) assert(block_cmp(&r[i], &b1[i], 1));
		else assert(block_cmp(&r[i], &b0[i], 1));
	}
	delete ot;
	delete[] b0;
	delete[] b1;
	delete[] r;
	delete[] b;
	return (double)t/TIME;
}
template<typename T>
double test_cot(NetIO * io, int party, int length, T* ot = nullptr, int TIME = 10) {
	block *b0 = new block[length], *r = new block[length];
	bool *b = new bool[length];
	block delta;
	PRG prg(fix_key);
	prg.random_block(&delta, 1);
	
	for(int i = 0; i < length; ++i) {
		b[i] = (rand()%2)==1;
	}

	long long t1 = 0, t = 0;
	io->sync();
	for(int i = 0; i < TIME; ++i) {
		t1 = timeStamp();
		if (ot == nullptr)
			ot = new T(io);
		if (party == ALICE) {
			ot->send_cot(b0, delta, length);
		} else {
			ot->recv_cot(r, b, length);
		}
		t += timeStamp()-t1;
	}
	if(party == ALICE)
			io->send_block(b0, length);
	else if(party == BOB)  {
			io->recv_block(b0, length);
		for(int i = 0; i < length; ++i) {
			block b1 = xorBlocks(b0[i], delta); 
			if (b[i]) assert(block_cmp(&r[i], &b1, 1));
			else assert(block_cmp(&r[i], &b0[i], 1));
		}
	}
	delete ot;
	delete[] b0;
	delete[] r;
	delete[] b;
	return (double)t/TIME;
}

template<typename T>
double test_rot(NetIO * io, int party, int length, T* ot = nullptr, int TIME = 10) {
	block *b0 = new block[length], *r = new block[length];
	block *b1 = new block[length];
	bool *b = new bool[length];
	PRG prg;
	
	long long t1 = 0, t = 0;
	io->sync();
	for(int i = 0; i < TIME; ++i) {
		prg.random_bool(b, length);
		t1 = timeStamp();
		if (ot == nullptr)
			ot = new T(io);
		if (party == ALICE) {
			ot->send_rot(b0, b1, length);
		} else {
			ot->recv_rot(r, b, length);
		}
		t += timeStamp()-t1;
	}
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
	delete ot;
	delete[] b0;
	delete[] b1;
	delete[] r;
	delete[] b;
	return (double)t/TIME;
}

int main(int argc, char** argv) {
	int length = 1<<23;
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr:SERVER_IP, port);
	io->set_nodelay();
	cout <<"1024 NPOT\t"<<test_ot<OTNP>(io, party, 1024)<<endl;
	cout <<length<<" Semi Honest OT Extension\t"<<test_ot<SHOTExtension>(io, party, length)<<endl;
	cout <<length<<" Semi Honest COT Extension\t"<<test_cot<SHOTExtension>(io, party, length)<<endl;
	cout <<length<<" Semi Honest ROT Extension\t"<<test_rot<SHOTExtension>(io, party, length)<<endl;
	delete io;
}
