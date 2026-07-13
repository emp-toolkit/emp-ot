#ifndef EMP_OT_BENCH_H_
#define EMP_OT_BENCH_H_
// Timing-only drivers for the bench_* harnesses. Each runs one protocol call,
// returns the elapsed microseconds, and (optionally) the wire bytes the call
// accrued. They do NOT verify correctness -- that lives in test.h's check_* /
// verify_rcot, used by the CI test_* drivers. Keeping the two apart means the
// reported throughput / B-per-OT figures are never contaminated by a
// verification round-trip, and benches never silently double as tests.
#include <emp-tool/emp-tool.h>
#include "emp-ot/emp-ot.h"
#include <cstring>
using namespace emp;

// Fault in a freshly allocated output buffer before the timer starts.
// A `new block[length]` is demand-zero mapped; without this, the kernel's
// first-touch page faults land inside the timed protocol call and get
// billed to the protocol -- on the cheap configs the fault cost is
// comparable to the whole compute budget. memset makes every page
// resident and writable up front.
inline void pretouch_blocks(block *p, int64_t n) {
	std::memset(p, 0, sizeof(block) * (size_t)n);
}

// Snap a requested RCOT length down to a whole number of SilentFerret
// rounds (one round = (t - refill_trees) * 2^tree_depth COTs). Ferret
// ships corrections per tree, but SilentFerret prepays whole rounds, so
// a partial tail round over-ships its corrections; at a whole-round
// length the two are wire-identical (the trace-hash baseline pins it)
// and their reported bits/RCOT compare directly.
inline int64_t snap_to_ferret_rounds(int64_t n, const PrimalLPNParameter& p) {
	const int64_t cpr = (p.t - p.refill_trees) << p.tree_depth;
	return n < cpr ? cpr : n / cpr * cpr;
}

// The connecting party (BOB / party 2) dials emp-tool's peer_ip() ($EMP_PEER_IP,
// default loopback); ALICE (party 1) listens and ignores it. So no bench
// hardcodes an IP.

// `bytes_sent_out` / `bytes_recv_out`: optional out-params receiving the wire
// bytes accrued by the timed protocol call only.

template <typename T>
double time_ot(T* ot, NetIO* io, int party, int64_t length,
               uint64_t* bytes_sent_out = nullptr,
               uint64_t* bytes_recv_out = nullptr) {
	block *b0 = new block[length], *b1 = new block[length], *r = new block[length];
	bool *b = new bool[length];
	PRG().random_bool(b, length);
	pretouch_blocks(b0, length); pretouch_blocks(b1, length); pretouch_blocks(r, length);
	io->sync();
	uint64_t s0 = io->send_counter, r0 = io->recv_counter;
	auto start = clock_start();
	if (party == ALICE) ot->send(b0, b1, length);
	else                ot->recv(r, b, length);
	io->flush();
	long long t = time_from(start);
	if (bytes_sent_out) *bytes_sent_out = io->send_counter - s0;
	if (bytes_recv_out) *bytes_recv_out = io->recv_counter - r0;
	delete[] b0; delete[] b1; delete[] r; delete[] b;
	return t;
}

template <typename T>
double time_cot(T* ot, NetIO* io, int party, int64_t length,
                uint64_t* bytes_sent_out = nullptr,
                uint64_t* bytes_recv_out = nullptr) {
	block *b0 = new block[length], *r = new block[length];
	bool *b = new bool[length];
	PRG().random_bool(b, length);
	pretouch_blocks(b0, length); pretouch_blocks(r, length);
	io->sync();
	uint64_t s0 = io->send_counter, r0 = io->recv_counter;
	auto start = clock_start();
	if (party == ALICE) ot->send_cot(b0, length);
	else                ot->recv_cot(r, b, length);
	io->flush();
	long long t = time_from(start);
	if (bytes_sent_out) *bytes_sent_out = io->send_counter - s0;
	if (bytes_recv_out) *bytes_recv_out = io->recv_counter - r0;
	delete[] b0; delete[] r; delete[] b;
	return t;
}

template <typename T>
double time_rot(T* ot, NetIO* io, int party, int64_t length,
                uint64_t* bytes_sent_out = nullptr,
                uint64_t* bytes_recv_out = nullptr) {
	block *b0 = new block[length], *b1 = new block[length], *r = new block[length];
	bool *b = new bool[length];
	PRG().random_bool(b, length);
	pretouch_blocks(b0, length); pretouch_blocks(b1, length); pretouch_blocks(r, length);
	io->sync();
	uint64_t s0 = io->send_counter, r0 = io->recv_counter;
	auto start = clock_start();
	if (party == ALICE) ot->send_rot(b0, b1, length);
	else                ot->recv_rot(r, b, length);
	io->flush();
	long long t = time_from(start);
	if (bytes_sent_out) *bytes_sent_out = io->send_counter - s0;
	if (bytes_recv_out) *bytes_recv_out = io->recv_counter - r0;
	delete[] b0; delete[] b1; delete[] r; delete[] b;
	return t;
}

template <typename T>
double time_rcot(T* ot, NetIO* io, int party, int64_t length,
                 uint64_t* bytes_sent_out = nullptr,
                 uint64_t* bytes_recv_out = nullptr) {
	block *b = new block[length];
	pretouch_blocks(b, length);
	io->sync();
	uint64_t s0 = io->send_counter, r0 = io->recv_counter;
	auto start = clock_start();
	ot->rcot(b, length);
	long long t = time_from(start);
	if (bytes_sent_out) *bytes_sent_out = io->send_counter - s0;
	if (bytes_recv_out) *bytes_recv_out = io->recv_counter - r0;
	delete[] b;
	return t;
}

// Streaming-API timing (begin / next / end). `length` is rounded down to a
// multiple of ot->chunk_size() (no leftover-buffer copy), reported via
// effective_length_out.
template <typename T>
double time_rcot_streaming(T* ot, NetIO* io, int party, int64_t length,
                           int64_t* effective_length_out = nullptr,
                           uint64_t* bytes_sent_out = nullptr,
                           uint64_t* bytes_recv_out = nullptr) {
	const int64_t chunk = ot->chunk_size();
	const int64_t n_chunks = length / chunk;
	const int64_t eff_len = n_chunks * chunk;
	if (effective_length_out) *effective_length_out = eff_len;
	block *b = new block[eff_len];
	pretouch_blocks(b, eff_len);
	io->sync();
	uint64_t s0 = io->send_counter, r0 = io->recv_counter;
	auto start = clock_start();
	ot->begin();
	for (int64_t i = 0; i < n_chunks; ++i) ot->next(b + i * chunk);
	ot->end();
	long long t = time_from(start);
	if (bytes_sent_out) *bytes_sent_out = io->send_counter - s0;
	if (bytes_recv_out) *bytes_recv_out = io->recv_counter - r0;
	delete[] b;
	return t;
}

#endif  // EMP_OT_BENCH_H_
