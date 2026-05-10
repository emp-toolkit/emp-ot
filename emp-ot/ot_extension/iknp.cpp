// Out-of-line definitions for IKNP. See iknp.h for the API surface.

#include "emp-ot/ot_extension/iknp.h"

namespace emp {

// Naming convention worth knowing: on the sender, `k0[i]` (and the
// derived `G0[i]`) is the base-OT-chosen key — i.e. whichever of the
// receiver's (k0_i, k1_i) matches s_i — NOT the literal "zero side".
// So sender's `G0[i]` plays the role of receiver's `G_{s_i}[i]`; the
// receiver's `G1[i]` has no sender counterpart (the un-chosen base
// key is unknown to the sender, which is the point of the base OT).
// The IKNP arithmetic relies on this: when s_i = 1,
//   q_i = G0_S[i].rand ⊕ u_i
//       = G1_R[i].rand ⊕ (G0_R[i].rand ⊕ G1_R[i].rand ⊕ r)
//       = G0_R[i].rand ⊕ r
// which gives the desired q_i ⊕ t_i = s_i · r per row.
void IKNP::setup_send(const bool *delta_bool_in) {
	is_sender = true;
	// bit_0(Δ) = 1 is required by the row-0 collapse (see class header).
	// Caller must pre-set delta_bool_in[0]; the random-Δ overload does
	// this internally.
	assert(delta_bool_in[0] && "IKNP::setup_send: delta_bool_in[0] must be true (bit_0(Δ) = 1 invariant)");
	memcpy(s, delta_bool_in, 128);
	block k0[128];
	if (malicious && !base_ot->is_malicious_secure())
		error("IKNP malicious mode requires a malicious-secure base OT");
	base_ot->recv(k0+1, s+1, 127);
	for (int64_t i = 1; i < 128; ++i)
		G0[i].reseed(&k0[i]);
	Delta = bool_to_block(s);
	setup_done = true;
	// is_sender as send_first matches FerretCOT's `party == ALICE` since
	// ALICE is sender by convention; both protocols can share an io.
	if (malicious && !io->fs_enabled())
		io->enable_fs(/*send_first=*/is_sender);
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
	if (malicious && !base_ot->is_malicious_secure())
		error("IKNP malicious mode requires a malicious-secure base OT");
	prg.random_block(k0, 128);
	prg.random_block(k1, 128);
	base_ot->send(k0+1, k1+1, 127);   // base_ot->send flushes internally
	for (int64_t i = 1; i < 128; ++i) {
		G0[i].reseed(&k0[i]);
		G1[i].reseed(&k1[i]);
	}
	setup_done = true;
	// See setup_send for the send_first convention.
	if (malicious && !io->fs_enabled())
		io->enable_fs(/*send_first=*/is_sender);
}

void IKNP::do_rcot_send_begin() {
	assert(setup_done && "rcot_send_begin: setup not done");
	assert(is_sender && "rcot_send_begin: not in sender role");
	if (malicious) check_q = makeBlock(0, 0);
}

void IKNP::do_rcot_send_end() {
	if (malicious) {
		// Sacrificial chunk: 128 extra OTs folded into check_q with chi
		// from the same Fiat-Shamir transcript as the real chunks. The
		// Q ⊕ T = R · Δ identity is linear in chi, so the final
		// check_q ⊕ check_x · Δ == check_t comparison still holds.
		// Built with the same do_rcot_send_next as a real chunk; the
		// extra block_size − 128 OTs in the chunk are simply unused
		// (the chi-fold over them still satisfies Q ⊕ T = R · Δ).
		BlockVec scratch(block_size);
		do_rcot_send_next(scratch.data());
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
}

// Row-by-row recv + compute, mirroring do_rcot_recv_next's interleave:
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
void IKNP::do_rcot_send_next(block *out) {
	block t[block_size];
	block tmp[block_size / 128];
	constexpr int64_t row_blocks = block_size / 128;
	memset(t, 0, block_size / 8);
	for (int64_t i = 1; i < 128; ++i) {
		io->recv_data(tmp, block_size / 8);
		G0[i].random_data(t + (i * row_blocks), block_size / 8);
		if (s[i])
			xorBlocks_arr(t + (i * row_blocks), t + (i * row_blocks),
			              tmp, row_blocks);
	}
	sse_trans((uint8_t *)(out), (uint8_t *)t, 128, block_size);

	if (malicious)
		combine_send(out);
}

// Sender-side fold: pack each 128-block chunk of `out` into Q_i and
// accumulate chi_i · Q_i into check_q. `out` is cache-hot from
// sse_trans. The chi seed is the IOChannel FS digest snapshot taken
// after this chunk's u-matrix bytes have been recv'd (and absorbed by
// FS).
void IKNP::combine_send(block *out) {
	PRG chiPRG;
	block seed = io->get_digest();
	chiPRG.reseed(&seed);
	block Q_i, chi, tmp;
	constexpr int64_t chunks = block_size / 128;
	for (int64_t i = 0; i < chunks; ++i) {
		packer.packing(&Q_i, out + 128 * i);
		chiPRG.random_block(&chi, 1);
		gfmul(chi, Q_i, &tmp);
		check_q = check_q ^ tmp;
	}
}

void IKNP::do_rcot_recv_begin() {
	assert(setup_done && "rcot_recv_begin: setup not done");
	assert(!is_sender && "rcot_recv_begin: not in receiver role");
	if (malicious) {
		check_t = makeBlock(0, 0);
		check_x = makeBlock(0, 0);
	}
}

void IKNP::do_rcot_recv_end() {
	if (malicious) {
		BlockVec scratch(block_size);
		do_rcot_recv_next(scratch.data());
		io->send_block(&check_x, 1);
		io->send_block(&check_t, 1);
	}
	// Recv-side rcot is send-only over its lifetime — the last
	// do_rcot_recv_next batch (and the malicious tail above) sit in
	// send_buf otherwise.
	io->flush();
}

// Sample r — the bit-packed choice vector. bit_k(r) is OT k's choice.
// Pinning t[0] = r below makes bit_0(out[k]) = bit_k(r) after sse_trans,
// so the choice lands in bit 0 of the output naturally. Row 0 is
// known-zero on both sides (sender forces q[0]=0, receiver pins
// t[0]=r post-loop), so skip it on the wire and in the transcript —
// only rows 1..127 are sent and hashed.
void IKNP::do_rcot_recv_next(block *out) {
	block r[block_size / 128];
	block t[block_size];
	block tmp[block_size / 128];
	constexpr int64_t row_blocks = block_size / 128;
	choice_prg.random_block(r, row_blocks);
	for (int64_t i = 1; i < 128; ++i) {
		G0[i].random_data(t + (i * row_blocks), block_size / 8);
		G1[i].random_data(tmp, block_size / 8);
		xorBlocks_arr(tmp, t + (i * row_blocks), tmp, row_blocks);
		xorBlocks_arr(tmp, r, tmp, row_blocks);
		io->send_data(tmp, block_size / 8);
	}
	// Pin t[0] = r so bit_0(out[k]) = bit_k(r) = choice_k after transpose.
	memcpy(t, r, block_size / 8);
	sse_trans((uint8_t *)(out), (uint8_t *)t, 128, block_size);

	if (malicious)
		combine_recv(out, r);
}

// Receiver-side fold: pack each 128-block chunk of `out` into T_i,
// take R_i = r[i] (the bit-packed choice block for chunk i), and
// accumulate chi_i · T_i into check_t and chi_i · R_i into check_x.
// Chi seed is the IOChannel FS digest, same snapshot point as the
// sender (after this chunk's u-matrix bytes crossed the wire) so
// per-chunk chi values match.
void IKNP::combine_recv(block *out, block *r) {
	PRG chiPRG;
	block seed = io->get_digest();
	chiPRG.reseed(&seed);
	block T_i, R_i, chi, tmp;
	constexpr int64_t chunks = block_size / 128;
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
