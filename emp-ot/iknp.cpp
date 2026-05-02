// Out-of-line definitions for IKNP. See iknp.h for the API surface.

#include "emp-ot/iknp.h"

namespace emp {

void IKNP::setup_send(const bool *delta_bool_in) {
	is_sender = true;
	memcpy(s, delta_bool_in, 128);
	block k0[128];
	OTCO base_ot(io);
	base_ot.recv(k0+1, s+1, 127);
	for (int64_t i = 1; i < 128; ++i)
		G0[i].reseed(&k0[i]);
	Delta = bool_to_block(s);
	setup_done = true;
}

void IKNP::setup_send() {
	bool s_random[128];
	prg.random_bool(s_random, 128);
	s_random[0] = true;  // bit_0(Δ) = 1 invariant; see class comment.
	setup_send(s_random);
}

void IKNP::setup_recv() {
	is_sender = false;
	block k0[128], k1[128];
	OTCO base_ot(io);
	prg.random_block(k0, 128);
	prg.random_block(k1, 128);
	base_ot.send(k0+1, k1+1, 127);   // OTCO::send flushes internally
	for (int64_t i = 1; i < 128; ++i) {
		G0[i].reseed(&k0[i]);
		G1[i].reseed(&k1[i]);
	}
	setup_done = true;
}

// One full session (begin → loop chunks → end). Auto-runs setup on
// first call so callers without a specific Δ to pin can just construct
// + use. Full block_size chunks land directly in `data` (cache-hot for
// the next stage); the non-aligned tail goes through a 128-block stack
// scratch since rcot_*_next writes ((len+127)/128)*128 blocks. The
// caller's `data` only has `tail` blocks of room past `aligned`, so it
// can't take the full output.
void IKNP::rcot_send(block *data, int64_t num) {
	if (!setup_done) setup_send();
	if (num <= 0) return;
	int64_t aligned = num & ~(int64_t)127;
	int64_t tail = num - aligned;
	rcot_send_begin();
	for (int64_t pos = 0; pos < aligned; pos += block_size) {
		int64_t chunk = std::min<int64_t>(block_size, aligned - pos);
		rcot_send_next(data + pos, chunk);
	}
	if (tail) {
		block scratch[128];
		rcot_send_next(scratch, tail);
		memcpy(data + aligned, scratch, sizeof(block) * tail);
	}
	rcot_send_end();
}

void IKNP::rcot_recv(block *data, int64_t num) {
	if (!setup_done) setup_recv();
	if (num <= 0) return;
	int64_t aligned = num & ~(int64_t)127;
	int64_t tail = num - aligned;
	rcot_recv_begin();
	for (int64_t pos = 0; pos < aligned; pos += block_size) {
		int64_t chunk = std::min<int64_t>(block_size, aligned - pos);
		rcot_recv_next(data + pos, chunk);
	}
	if (tail) {
		block scratch[128];
		rcot_recv_next(scratch, tail);
		memcpy(data + aligned, scratch, sizeof(block) * tail);
	}
	rcot_recv_end();
}

void IKNP::rcot_send_begin() {
	assert(is_sender && "rcot_send_begin: not in sender role");
	assert(!in_send_session && "rcot_send_begin: previous session not ended");
	in_send_session = true;
	if (malicious) {
		transcript.reset();
		check_q = makeBlock(0, 0);
	}
}

void IKNP::rcot_send_end() {
	assert(in_send_session && "rcot_send_end: no active session");
	if (malicious) {
		// Sacrificial chunk: 128 extra OTs folded into check_q with chi
		// from the same Fiat-Shamir transcript as the real chunks. The
		// Q ⊕ T = R · Δ identity is linear in chi, so the final
		// check_q ⊕ check_x · Δ == check_t comparison still holds.
		block scratch[128];
		rcot_send_next(scratch, 128);
		// Receiver opens (check_x, check_t); accept iff
		// check_q ⊕ check_x · Δ == check_t.
		block x, t, tmp;
		io->recv_block(&x, 1);
		io->recv_block(&t, 1);
		gfmul(x, Delta, &tmp);
		check_q = check_q ^ tmp;
		if (!cmpBlock(&check_q, &t, 1))
			error("OT Extension check failed");
	}
	in_send_session = false;
}

// Row-by-row recv + compute, mirroring rcot_recv_next's interleave:
// the receiver sends the u-matrix one row at a time, so we read one
// row, fold it into the transcript, and combine it with G0[i] before
// the next read — keeping `tmp` to a single row and pipelining the
// network with the per-row XOR work.
//
// Row 0 forced to 0: with bit_0(Delta) = s[0] = 1 the IKNP relation at
// bit 0 becomes 0 ^ bit_0(M_k) = r[k] · 1, so bit_0(M_k) = choice
// directly. Both sides skip row 0 on the wire and in the transcript
// (both know it's zeros), so only rows 1..127 are exchanged and hashed
// — same chi seed on both sides.
void IKNP::rcot_send_next(block *out, int64_t len) {
	assert(in_send_session && "rcot_send_next: call rcot_send_begin first");
	block t[block_size];
	block tmp[block_size / 128];
	int64_t rounded_len = (len + 127) / 128 * 128;
	int64_t row_blocks = rounded_len / 128;
	memset(t, 0, rounded_len / 8);
	for (int64_t i = 1; i < 128; ++i) {
		io->recv_data(tmp, rounded_len / 8);
		if (malicious)
			transcript.put(tmp, rounded_len / 8);
		G0[i].random_data(t + (i * row_blocks), rounded_len / 8);
		if (s[i])
			xorBlocks_arr(t + (i * row_blocks), t + (i * row_blocks),
			              tmp, row_blocks);
	}
	sse_trans((uint8_t *)(out), (uint8_t *)t, 128, rounded_len);

	if (malicious)
		combine_send(out, rounded_len);
}

// Sender-side fold: pack each 128-block chunk of `out` into Q_i and
// accumulate chi_i · Q_i into check_q. `out` is cache-hot from
// sse_trans. The chi seed is a snapshot of the transcript taken after
// this chunk's u-matrix was put. Caller passes rounded_len (always a
// multiple of 128) so every chunk is fully populated — folding only
// the user-requested `len` would zero-pad the tail and break the
// Q_i ⊕ T_i = R_i · Δ identity at the unused positions, since the
// receiver's r tail is random.
void IKNP::combine_send(block *out, int64_t rounded_len) {
	PRG chiPRG;
	block seed;
	char dgst[Hash::DIGEST_SIZE];
	transcript.digest(dgst, /*reset_after=*/false);
	memcpy(&seed, dgst, sizeof(block));
	chiPRG.reseed(&seed);
	block Q_i, chi, tmp;
	int64_t chunks = rounded_len / 128;
	for (int64_t i = 0; i < chunks; ++i) {
		packer.packing(&Q_i, out + 128 * i);
		chiPRG.random_block(&chi, 1);
		gfmul(chi, Q_i, &tmp);
		check_q = check_q ^ tmp;
	}
}

void IKNP::rcot_recv_begin() {
	assert(!is_sender && "rcot_recv_begin: not in receiver role");
	assert(!in_recv_session && "rcot_recv_begin: previous session not ended");
	in_recv_session = true;
	if (malicious) {
		transcript.reset();
		check_t = makeBlock(0, 0);
		check_x = makeBlock(0, 0);
	}
}

void IKNP::rcot_recv_end() {
	assert(in_recv_session && "rcot_recv_end: no active session");
	if (malicious) {
		block scratch[128];
		rcot_recv_next(scratch, 128);
		io->send_block(&check_x, 1);
		io->send_block(&check_t, 1);
	}
	// Recv-side rcot is send-only over its lifetime — the last
	// rcot_recv_next batch (and the malicious tail above) sit in send_buf
	// otherwise.
	io->flush();
	in_recv_session = false;
}

// Sample r — the bit-packed choice vector. bit_k(r) is OT k's choice.
// Pinning t[0] = r below makes bit_0(out[k]) = bit_k(r) after sse_trans,
// so the choice lands in bit 0 of the output naturally. Row 0 is
// known-zero on both sides (sender forces q[0]=0, receiver pins
// t[0]=r post-loop), so skip it on the wire and in the transcript —
// only rows 1..127 are sent and hashed.
void IKNP::rcot_recv_next(block *out, int64_t len) {
	assert(in_recv_session && "rcot_recv_next: call rcot_recv_begin first");
	block r[block_size / 128];
	block t[block_size];
	block tmp[block_size / 128];
	int64_t rounded_len = (len + 127) / 128 * 128;
	choice_prg.random_block(r, rounded_len / 128);
	for (int64_t i = 1; i < 128; ++i) {
		G0[i].random_data(t + (i * rounded_len / 128), rounded_len / 8);
		G1[i].random_data(tmp, rounded_len / 8);
		xorBlocks_arr(tmp, t + (i * rounded_len / 128), tmp, rounded_len / 128);
		xorBlocks_arr(tmp, r, tmp, rounded_len / 128);
		if (malicious)
			transcript.put(tmp, rounded_len / 8);
		io->send_data(tmp, rounded_len / 8);
	}
	// Pin t[0] = r so bit_0(out[k]) = bit_k(r) = choice_k after transpose.
	memcpy(t, r, rounded_len / 8);
	sse_trans((uint8_t *)(out), (uint8_t *)t, 128, rounded_len);

	if (malicious)
		combine_recv(out, r, rounded_len);
}

// Receiver-side fold: pack each 128-block chunk of `out` into T_i,
// take R_i = r[i] (the bit-packed choice block for chunk i), and
// accumulate chi_i · T_i into check_t and chi_i · R_i into check_x.
// Same snapshot-based chi seeding as the sender so per-chunk chi
// values match. Caller passes rounded_len; out has rounded_len valid
// IKNP outputs and r has rounded_len/128 valid choice blocks even
// when len isn't a multiple of 128 (the tail OTs / choice bits are
// unused upstream but still satisfy Q ⊕ T = R · Δ here, which is
// what the chi-fold needs).
void IKNP::combine_recv(block *out, block *r, int64_t rounded_len) {
	PRG chiPRG;
	block seed;
	char dgst[Hash::DIGEST_SIZE];
	transcript.digest(dgst, /*reset_after=*/false);
	memcpy(&seed, dgst, sizeof(block));
	chiPRG.reseed(&seed);
	block T_i, R_i, chi, tmp;
	int64_t chunks = rounded_len / 128;
	for (int64_t i = 0; i < chunks; ++i) {
		packer.packing(&T_i, out + 128 * i);
		R_i = r[i];
		chiPRG.random_block(&chi, 1);
		gfmul(chi, T_i, &tmp);
		check_t = check_t ^ tmp;
		gfmul(chi, R_i, &tmp);
		check_x = check_x ^ tmp;
	}
}

}  // namespace emp
