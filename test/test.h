#ifndef EMP_OT_TEST_H_
#define EMP_OT_TEST_H_
// Correctness-only drivers for the CI test_* harnesses. Each runs one protocol
// call and validates the outputs via expecting() (NOT assert(), which is
// compiled out under NDEBUG) -- never times anything. Throughput timing lives in bench.h's
// time_*, used by the manual bench_* harnesses. verify_rcot is the shared
// output-checker reused by both check_rcot variants and the trace_* harnesses.
#include <emp-tool/emp-tool.h>
#include "emp-ot/emp-ot.h"
#include <iostream>
using namespace emp;

template <typename T>
void check_ot(T* ot, NetIO* io, int party, int64_t length) {
	block *b0 = new block[length], *b1 = new block[length], *r = new block[length];
	// Shared PRG seed so both parties draw the same (b0, b1); BOB then checks
	// its received r against its own copy -- no extra exchange needed.
	block test_seed;
	if (party == ALICE) { PRG().random_block(&test_seed, 1); io->send_data(&test_seed, sizeof(block)); }
	else                { io->recv_data(&test_seed, sizeof(block)); }
	io->flush();
	PRG prg(&test_seed);
	prg.random_block(b0, length);
	prg.random_block(b1, length);
	bool *b = new bool[length];
	PRG().random_bool(b, length);
	if (party == ALICE) ot->send(b0, b1, length);
	else                ot->recv(r, b, length);
	io->flush();
	if (party == BOB)
		for (int64_t i = 0; i < length; ++i)
			if (!cmpBlock(&r[i], b[i] ? &b1[i] : &b0[i], 1)) {
				std::cout << i << "\n";
				expecting(false, "OT failed");
			}
	std::cout << "Tests passed.\t";
	delete[] b0; delete[] b1; delete[] r; delete[] b;
}

template <typename T>
void check_cot(T* ot, NetIO* io, int party, int64_t length) {
	block *b0 = new block[length], *r = new block[length];
	bool *b = new bool[length];
	block delta;
	PRG prg; prg.random_block(&delta, 1); prg.random_bool(b, length);
	io->sync();
	if (party == ALICE) { ot->send_cot(b0, length); delta = ot->Delta; }
	else                  ot->recv_cot(r, b, length);
	io->flush();
	if (party == ALICE) { io->send_block(&delta, 1); io->send_block(b0, length); }
	else if (party == BOB) {
		io->recv_block(&delta, 1);
		io->recv_block(b0, length);
		for (int64_t i = 0; i < length; ++i) {
			block b1 = b0[i] ^ delta;
			expecting(cmpBlock(&r[i], b[i] ? &b1 : &b0[i], 1),
			          "COT failed");
		}
	}
	std::cout << "Tests passed.\t";
	io->flush();
	delete[] b0; delete[] r; delete[] b;
}

template <typename T>
void check_rot(T* ot, NetIO* io, int party, int64_t length) {
	block *b0 = new block[length], *b1 = new block[length], *r = new block[length];
	bool *b = new bool[length];
	PRG().random_bool(b, length);
	io->sync();
	if (party == ALICE) ot->send_rot(b0, b1, length);
	else                ot->recv_rot(r, b, length);
	io->flush();
	if (party == ALICE) { io->send_block(b0, length); io->send_block(b1, length); }
	else if (party == BOB) {
		io->recv_block(b0, length);
		io->recv_block(b1, length);
		for (int64_t i = 0; i < length; ++i)
			expecting(cmpBlock(&r[i], b[i] ? &b1[i] : &b0[i], 1),
			          "ROT failed");
	}
	std::cout << "Tests passed.\t";
	io->flush();
	delete[] b0; delete[] b1; delete[] r; delete[] b;
}

// Verify the receiver's RCOT outputs against the sender's: receiver XORs
// ch[LSB(b[i])] (= 0 if LSB=0, = Δ if LSB=1) into each block; result must
// equal sender's b. Requires the LSB-of-output choice convention
// (LSB(K)=0, LSB(M)=b_intrinsic) and LSB(Δ)=1.
template <typename T>
void verify_rcot(T* ot, NetIO* io, int party, block* b, int64_t mem_size) {
	io->sync();
	if (party == ALICE) {
		io->send_block(&ot->Delta, 1);
		io->send_block(b, mem_size);
	} else if (party == BOB) {
		block ch[2];
		ch[0] = zero_block;
		block *b0 = new block[mem_size];
		io->recv_block(ch + 1, 1);
		io->recv_block(b0, mem_size);
		for (int64_t i = 0; i < mem_size; ++i) b[i] = b[i] ^ ch[getLSB(b[i])];
		expecting(cmpBlock(b, b0, mem_size), "RCOT failed");
		delete[] b0;
	}
	std::cout << "Tests passed.\t";
}

// One-shot RCOT correctness: rcot() then verify.
template <typename T>
void check_rcot(T* ot, NetIO* io, int party, int64_t length) {
	block *b = new block[length];
	ot->rcot(b, length);
	verify_rcot(ot, io, party, b, length);
	delete[] b;
}

// Streaming-API RCOT correctness (begin / next / end); length rounded down to a
// chunk_size() multiple.
template <typename T>
void check_rcot_streaming(T* ot, NetIO* io, int party, int64_t length) {
	const int64_t chunk = ot->chunk_size();
	const int64_t eff_len = (length / chunk) * chunk;
	block *b = new block[eff_len];
	ot->begin();
	for (int64_t i = 0; i < eff_len; i += chunk) ot->next(b + i);
	ot->end();
	verify_rcot(ot, io, party, b, eff_len);
	delete[] b;
}

#endif  // EMP_OT_TEST_H_
