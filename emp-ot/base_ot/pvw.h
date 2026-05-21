#ifndef EMP_OTPVW_H__
#define EMP_OTPVW_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/ot.h"
#include <vector>

namespace emp {

/*
 * Peikert-Vaikuntanathan-Waters OT (PVW '08), RO-derived CRS.
 * [REF] "A Framework for Efficient and Composable Oblivious Transfer"
 *       https://eprint.iacr.org/2007/348
 *
 * Setup. Both parties derive (g_0, g_1, h_0, h_1) by hash-to-curve from
 * fixed CRS labels. With independent random points the CRS is non-DH
 * (messy mode): sender-statistical security; receiver-computational
 * under DDH.
 *
 *   Recv:  r <- Z_q ; send (g, h) = (g_sigma^r, h_sigma^r).
 *   Send:  for b in {0,1}: s_b, t_b <- Z_q ; send (u_b, c_b):
 *            u_b = g_b^{s_b} * h_b^{t_b}     // consistency check on CRS bases
 *            c_b = g^{s_b}  * h^{t_b}  * x_b // masked under receiver's (g, h)
 *   Recv:  output x_sigma = c_sigma / u_sigma^r.
 * */
class OTPVW: public OT { public:
	// Messy-mode PVW: receiver-secure under DDH against a malicious
	// sender; sender statistically secure against a malicious receiver.
	bool is_malicious_secure() const override { return true; }

	ECGroup G;

	Point g0, g1, h0, h1;
	bool crs_ready_ = false;

	OTPVW(IOChannel* io_) { this->io = io_; }

	// Derive the CRS lazily on first use so it binds the session id (set
	// via OT::set_sid after construction). Both parties derive identical,
	// non-DH points from the shared sid.
	void ensure_crs_() {
		if (crs_ready_) return;
		static const char *labels[4] = {
			"CRS g0 for C:PeiVaiWat08",
			"CRS g1 for C:PeiVaiWat08",
			"CRS h0 for C:PeiVaiWat08",
			"CRS h1 for C:PeiVaiWat08",
		};
		Point *crs[4] = {&g0, &g1, &h0, &h1};
		for (int i = 0; i < 4; ++i)
			*crs[i] = RO("emp-ot:pvw-base-ot:crs", sid.value())
			              .absorb(std::string_view(labels[i])).squeeze_point(G);
		crs_ready_ = true;
	}

	void send(const block* data0, const block* data1, int64_t length) override {
		ensure_crs_();
		// Per i: receive (g_i, h_i), build (u_b, c_b) for b in {0,1},
		// send them and the ciphertexts. (g_i, h_i) is consumed within
		// the iteration so no length-sized staging array is needed.
		for (int64_t i = 0; i < length; ++i) {
			Point gs_i, hs_i;
			io->recv_pt(&G, &gs_i);
			io->recv_pt(&G, &hs_i);

			Point xb[2];
			for (int b = 0; b < 2; ++b) {
				Scalar s = G.rand_scalar();
				Scalar t = G.rand_scalar();
				// x_b is a fresh random group element used only as KDF
				// input; cheapest way to sample uniformly is g^k for a
				// random scalar k.
				Scalar k = G.rand_scalar();
				xb[b] = G.mul_gen(k);

				const Point &gb = (b == 0 ? g0 : g1);
				const Point &hb = (b == 0 ? h0 : h1);
				Point u    = gb.mul(s).add(hb.mul(t));
				Point c_pt = gs_i.mul(s).add(hs_i.mul(t)).add(xb[b]);
				io->send_pt(&u);
				io->send_pt(&c_pt);
			}
			block ct[2];
			ct[0] = RO("emp-ot:pvw-base-ot:kdf", sid.value()).absorb(xb[0]).absorb((uint64_t)i).squeeze_block() ^ data0[i];
			ct[1] = RO("emp-ot:pvw-base-ot:kdf", sid.value()).absorb(xb[1]).absorb((uint64_t)i).squeeze_block() ^ data1[i];
			io->send_data(ct, 2 * sizeof(block));
		}
		io->flush();
	}

	void recv(block* data, const bool* b, int64_t length) override {
		ensure_crs_();
		// Round 1: send (g, h) = (g_sigma^r, h_sigma^r) per OT instance.
		// r_i is needed across rounds (used to recover x_sigma in round
		// 2), so keep all r_i live in an array.
		std::vector<Scalar> rs(length);
		for (int64_t i = 0; i < length; ++i) {
			rs[i] = G.rand_scalar();
			int sigma = b[i] ? 1 : 0;
			const Point &g_base = (sigma == 0 ? g0 : g1);
			const Point &h_base = (sigma == 0 ? h0 : h1);
			Point g_send = g_base.mul(rs[i]);
			Point h_send = h_base.mul(rs[i]);
			io->send_pt(&g_send);
			io->send_pt(&h_send);
		}

		// Round 2: receive (u_b, c_b) for each b, plus ciphertexts.
		// Recover x_sigma = c_sigma / u_sigma^r and decrypt ct_sigma.
		for (int64_t i = 0; i < length; ++i) {
			int sigma = b[i] ? 1 : 0;
			Point u[2], c_pt[2];
			for (int bb = 0; bb < 2; ++bb) {
				io->recv_pt(&G, &u[bb]);
				io->recv_pt(&G, &c_pt[bb]);
			}
			block ct[2];
			io->recv_data(ct, 2 * sizeof(block));

			// Additive EC notation: x_sigma = c_sigma - (r · u_sigma).
			// Multiplicative: x_sigma = c_sigma / u_sigma^r.
			Point u_r = u[sigma].mul(rs[i]);
			Point x_sigma = c_pt[sigma].add(u_r.inv());

			data[i] = RO("emp-ot:pvw-base-ot:kdf", sid.value()).absorb(x_sigma).absorb((uint64_t)i).squeeze_block() ^ ct[sigma];
		}
	}
};

}  // namespace emp
#endif
