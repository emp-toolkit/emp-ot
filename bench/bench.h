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
#include <cstdlib>   // std::getenv
using namespace emp;

// Peer address for the connecting party (BOB / party 2). A networked two-box
// run exports EMP_BENCH_HOST=<ALICE's address>; unset falls back to loopback --
// the default single-box `run`-script setup. ALICE (party 1) listens and
// ignores this. So no bench hardcodes an IP: localhost by default, the peer's
// address when EMP_BENCH_HOST is set.
inline const char* bench_peer_host() {
    const char* h = std::getenv("EMP_BENCH_HOST");
    return (h != nullptr && *h != '\0') ? h : "127.0.0.1";
}

// `bytes_sent_out` / `bytes_recv_out`: optional out-params receiving the wire
// bytes accrued by the timed protocol call only.

template <typename T>
double time_ot(T* ot, NetIO* io, int party, int64_t length,
               uint64_t* bytes_sent_out = nullptr,
               uint64_t* bytes_recv_out = nullptr) {
	block *b0 = new block[length], *b1 = new block[length], *r = new block[length];
	bool *b = new bool[length];
	PRG().random_bool(b, length);
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
