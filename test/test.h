#include <emp-tool/emp-tool.h>
#include "emp-ot/emp-ot.h"
#include <iostream>
using namespace emp;

// `bytes_sent_out` / `bytes_recv_out`: optional out-params. When non-null,
// receive the wire bytes accrued by the protocol call only — i.e. excluding
// the verification round-trip the test harness runs after `time_from` to
// check OT correctness. Use these for any reported B/COT figures.
template <typename T>
double test_ot(T * ot, NetIO *io, int party, int64_t length,
               uint64_t* bytes_sent_out = nullptr,
               uint64_t* bytes_recv_out = nullptr) {
	block *b0 = new block[length], *b1 = new block[length],
	*r = new block[length];
	PRG prg(fix_key);
	prg.random_block(b0, length);
	prg.random_block(b1, length);
	bool *b = new bool[length];
	PRG prg2;
	prg2.random_bool(b, length);

	uint64_t s0 = io->bytes_sent, r0 = io->bytes_recv;
	auto start = clock_start();
	if (party == ALICE) {
		ot->send(b0, b1, length);
	} else {
		ot->recv(r, b, length);
	}
	io->flush();
	long long t = time_from(start);
	if (bytes_sent_out) *bytes_sent_out = io->bytes_sent - s0;
	if (bytes_recv_out) *bytes_recv_out = io->bytes_recv - r0;
	if (party == BOB) {
		for (int64_t i = 0; i < length; ++i) {
			if (b[i]){ if(!cmpBlock(&r[i], &b1[i], 1)) {
				std::cout <<i<<"\n";
				error("wrong!\n");
			}}
			else { if(!cmpBlock(&r[i], &b0[i], 1)) {
				std::cout <<i<<"\n";
				error("wrong!\n");
			}}
		}
	}
	std::cout << "Tests passed.\t";
	delete[] b0;
	delete[] b1;
	delete[] r;
	delete[] b;
	return t;
}


template <typename T>
double test_cot(T * ot, NetIO *io, int party, int64_t length,
                uint64_t* bytes_sent_out = nullptr,
                uint64_t* bytes_recv_out = nullptr) {
	block *b0 = new block[length], *r = new block[length];
	bool *b = new bool[length];
	block delta;
	PRG prg;
	prg.random_block(&delta, 1);
	prg.random_bool(b, length);

	io->sync();
	uint64_t s0 = io->bytes_sent, r0 = io->bytes_recv;
	auto start = clock_start();
	if (party == ALICE) {
		ot->send_cot(b0, length);
		delta = ot->Delta;
	} else {
		ot->recv_cot(r, b, length);
	}
	io->flush();
	long long t = time_from(start);
	if (bytes_sent_out) *bytes_sent_out = io->bytes_sent - s0;
	if (bytes_recv_out) *bytes_recv_out = io->bytes_recv - r0;
	if (party == ALICE) {
		io->send_block(&delta, 1);
		io->send_block(b0, length);
	}
	else if (party == BOB) {
		io->recv_block(&delta, 1);
		io->recv_block(b0, length);
		for (int64_t i = 0; i < length; ++i) {
			block b1 = b0[i] ^ delta;
			if (b[i]) {
				if (!cmpBlock(&r[i], &b1, 1))
					error("COT failed!");
			} else {
				if (!cmpBlock(&r[i], &b0[i], 1))
					error("COT failed!");
			}
		}
	}
	std::cout << "Tests passed.\t";
	io->flush();
	delete[] b0;
	delete[] r;
	delete[] b;
	return t;
}

template <typename T>
double test_rot(T* ot, NetIO *io, int party, int64_t length,
                uint64_t* bytes_sent_out = nullptr,
                uint64_t* bytes_recv_out = nullptr) {
	block *b0 = new block[length], *r = new block[length];
	block *b1 = new block[length];
	bool *b = new bool[length];
	PRG prg;
	prg.random_bool(b, length);

	io->sync();
	uint64_t s0 = io->bytes_sent, r0 = io->bytes_recv;
	auto start = clock_start();
	if (party == ALICE) {
		ot->send_rot(b0, b1, length);
	} else {
		ot->recv_rot(r, b, length);
	}
	io->flush();
	long long t = time_from(start);
	if (bytes_sent_out) *bytes_sent_out = io->bytes_sent - s0;
	if (bytes_recv_out) *bytes_recv_out = io->bytes_recv - r0;
	if (party == ALICE) {
		io->send_block(b0, length);
		io->send_block(b1, length);
	} else if (party == BOB) {
		io->recv_block(b0, length);
		io->recv_block(b1, length);
		for (int64_t i = 0; i < length; ++i) {
			if (b[i])
				assert(cmpBlock(&r[i], &b1[i], 1));
			else
				assert(cmpBlock(&r[i], &b0[i], 1));
		}
	}
	std::cout << "Tests passed.\t";
	io->flush();
	delete[] b0;
	delete[] b1;
	delete[] r;
	delete[] b;
	return t;
}

// Verify the receiver's RCOT outputs against the sender's: receiver
// XORs ch[LSB(b[i])] (= 0 if LSB=0, = Δ if LSB=1) into each block;
// result must equal sender's b. Requires the LSB-of-output choice
// convention (LSB(K)=0, LSB(M)=b_intrinsic) and LSB(Δ)=1.
template <typename T>
static void verify_rcot(T* ot, NetIO* io, int party, block* b, int64_t mem_size) {
	io->sync();
	if (party == ALICE) {
		io->send_block(&ot->Delta, 1);
		io->send_block(b, mem_size);
	} else if (party == BOB) {
		block ch[2];
		ch[0] = zero_block;
		block *b0 = new block[mem_size];
		io->recv_block(ch+1, 1);
		io->recv_block(b0, mem_size);
		for (int64_t i = 0; i < mem_size; ++i) {
			b[i] = b[i] ^ ch[getLSB(b[i])];
		}
		if (!cmpBlock(b, b0, mem_size))
			error("RCOT failed");
		delete[] b0;
	}
	std::cout << "Tests passed.\t";
}

template <typename T>
double test_rcot(T* ot, NetIO *io, int party, int64_t length,
                 uint64_t* bytes_sent_out = nullptr,
                 uint64_t* bytes_recv_out = nullptr) {
	block *b = new block[length];
	io->sync();
	uint64_t s0 = io->bytes_sent, r0 = io->bytes_recv;
	auto start = clock_start();
	if (party == ALICE) ot->rcot_send(b, length);
	else                ot->rcot_recv(b, length);
	long long t = time_from(start);
	if (bytes_sent_out) *bytes_sent_out = io->bytes_sent - s0;
	if (bytes_recv_out) *bytes_recv_out = io->bytes_recv - r0;
	verify_rcot(ot, io, party, b, length);
	delete[] b;
	return t;
}
