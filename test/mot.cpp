//#include "emp-ot.h"
#include "emp-ot"
#include <emp-tool>
#include <iostream>
using namespace std;

template<typename T>
double test_com_ot(NetIO * io, int party, int length, T* ot = nullptr, int TIME = 10) {
	block *b0 = new block[length], *b1 = new block[length], *r = new block[length], *op = new block[length];
	bool *b = new bool[length];
	PRG prg(fix_key);
	prg.random_block(b0, length);
	prg.random_block(b1, length);
	prg.random_bool(b, length);

	long long t1 = 0, t = 0;
	io->sync();
	io->set_nodelay();
	for(int i = 0; i < TIME; ++i) {
		t1 = timeStamp();
		ot = new T(io, true);
		if (party == ALICE) {
			ot->send(b0, b1, length);
			ot->open();
		} else {
			ot->recv(r, b, length);
			ot->open(op, b, length);
		}
		t += timeStamp()-t1;
		delete ot;
	}
	if(party == BOB) for(int i = 0; i < length; ++i) {
		if (b[i]) {
			assert(block_cmp(&r[i], &b1[i], 1));
			assert(block_cmp(&op[i], &b0[i], 1));
		}
		else {
			assert(block_cmp(&r[i], &b0[i], 1));
			assert(block_cmp(&op[i], &b1[i], 1));
		}
	}
	delete[] b0;
	delete[] b1;
	delete[] r;
	delete[] b;
	delete[] op;
	return (double)t/TIME;
}


template<typename T>
double test_ot(NetIO * io, int party, int length, T* ot = nullptr, int TIME = 10) {
	block *b0 = new block[length], *b1 = new block[length], *r = new block[length];
	bool *b = new bool[length];
	PRG prg(fix_key);
	prg.random_block(b0, length);
	prg.random_block(b1, length);
	prg.random_bool(b, length);

	long long t1 = 0, t = 0;
	io->sync();
	io->set_nodelay();
	for(int i = 0; i < TIME; ++i) {
		t1 = timeStamp();
		ot = new T(io);
		if (party == ALICE) {
			ot->send(b0, b1, length);
		} else {
			ot->recv(r, b, length);
		}
		t += timeStamp()-t1;
		delete ot;
	}
	if(party == BOB) for(int i = 0; i < length; ++i) {
		if (b[i]) assert(block_cmp(&r[i], &b1[i], 1));
		else assert(block_cmp(&r[i], &b0[i], 1));
	}
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
	io->set_nodelay();
	for(int i = 0; i < TIME; ++i) {
		t1 = timeStamp();
		ot = new T(io);
		if (party == ALICE) {
			ot->send_cot(b0, delta, length);
		} else {
			ot->recv_cot(r, b, length);
		}
		t += timeStamp()-t1;
		delete ot;
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

	for(int i = 0; i < length; ++i) {
		b[i] = (rand()%2)==1;
	}

	long long t1 = 0, t = 0;
	io->sync();
	io->set_nodelay();
	for(int i = 0; i < TIME; ++i) {
		t1 = timeStamp();
		ot = new T(io);
		if (party == ALICE) {
			ot->send_rot(b0, b1, length);
		} else {
			ot->recv_rot(r, b, length);
		}
		t += timeStamp()-t1;
		delete ot;
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
	delete[] b0;
	delete[] b1;
	delete[] r;
	delete[] b;
	return (double)t/TIME;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	NetIO * io = new NetIO(party==ALICE ? nullptr:SERVER_IP, port);
	cout <<"COOT\t"<<test_ot<OTCO>(io, party, 1024)<<endl;
	cout <<"8M Malicious OT Extension (KOS)\t"<<test_ot<MOTExtension_KOS>(io, party, 1<<23)<<endl;
	cout <<"8M Malicious OT Extension (ALSZ)\t"<<test_ot<MOTExtension_ALSZ>(io, party, 1<<23)<<endl;
	cout <<"8M Malicious Committing OT Extension (KOS)\t"<<test_com_ot<MOTExtension_KOS>(io, party, 1<<23)<<endl;
	cout <<"8M Malicious Committing OT Extension (ALSZ)\t"<<test_com_ot<MOTExtension_ALSZ>(io, party, 1<<23)<<endl;
	delete io;
}
