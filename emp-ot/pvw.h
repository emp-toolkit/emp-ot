#ifndef EMP_OTPVW_H__
#define EMP_OTPVW_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/ot.h"
#include <vector>

namespace emp {

/*
 * Peikert-Vaikuntanathan-Waters OT (PVW '08), RO-derived CRS, messy mode.
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
 *
 * Correctness for b = sigma:
 *   c_sigma   = (g_sigma^r)^{s_sigma} * (h_sigma^r)^{t_sigma} * x_sigma
 *             = g_sigma^{r·s_sigma} * h_sigma^{r·t_sigma} * x_sigma
 *   u_sigma^r = (g_sigma^{s_sigma} * h_sigma^{t_sigma})^r
 *             = g_sigma^{r·s_sigma} * h_sigma^{r·t_sigma}
 *   c_sigma / u_sigma^r = x_sigma  (the masking term cancels exactly).
 *
 * For b ≠ sigma the bases differ (g_{1-sigma}/h_{1-sigma} in u_b vs
 * g_sigma/h_sigma in c_b), so u_b^r doesn't match the masking — the
 * receiver gets a uniform-looking element, not x_{1-sigma}.
 *
 * Block-OT layer: x_b is a fresh random group element used only as key
 * material. The actual block payload is transmitted as
 *   ciphertext_b = data_b XOR KDF(x_b)
 * sent alongside (u_b, c_b). Receiver recovers x_sigma, decrypts
 * ciphertext_sigma.
 */
class OTPVW: public OT { public:
	IOChannel* io;
	Group *G = nullptr;
	bool delete_G = true;

	Point g0, g1, h0, h1;

	OTPVW(IOChannel* io, Group* _G = nullptr) {
		this->io = io;
		if (_G == nullptr) {
			G = new Group();
		} else {
			G = _G;
			delete_G = false;
		}
		// CRS labels — both parties derive identical points.
		static const char *labels[4] = {
			"CRS g0 for C:PeiVaiWat08",
			"CRS g1 for C:PeiVaiWat08",
			"CRS h0 for C:PeiVaiWat08",
			"CRS h1 for C:PeiVaiWat08",
		};
		Point *crs[4] = {&g0, &g1, &h0, &h1};
		for (int i = 0; i < 4; ++i)
			G->hash_to_point(labels[i], strlen(labels[i]), *crs[i]);
	}

	~OTPVW() {
		if (delete_G) delete G;
	}

	void send(const block* data0, const block* data1, int64_t length) override {
		// Per i: receive (g_i, h_i), build (u_b, c_b) for b in {0,1},
		// send them and the ciphertexts. (g_i, h_i) is consumed within
		// the iteration so no length-sized staging array is needed.
		for (int64_t i = 0; i < length; ++i) {
			Point gs_i, hs_i;
			io->recv_pt(G, &gs_i);
			io->recv_pt(G, &hs_i);

			BigInt s, t, k;
			Point xb[2];
			for (int b = 0; b < 2; ++b) {
				G->get_rand_bn(s);
				G->get_rand_bn(t);
				// x_b is a fresh random group element used only as KDF
				// input; cheapest way to sample uniformly is g^k for a
				// random scalar k.
				G->get_rand_bn(k);
				xb[b] = G->mul_gen(k);

				const Point &gb = (b == 0 ? g0 : g1);
				const Point &hb = (b == 0 ? h0 : h1);
				Point u    = gb.mul(s).add(hb.mul(t));
				Point c_pt = gs_i.mul(s).add(hs_i.mul(t)).add(xb[b]);
				io->send_pt(&u);
				io->send_pt(&c_pt);
			}
			block ct[2];
			ct[0] = Hash::KDF(xb[0], i) ^ data0[i];
			ct[1] = Hash::KDF(xb[1], i) ^ data1[i];
			io->send_data(ct, 2 * sizeof(block));
		}
		io->flush();
	}

	void recv(block* data, const bool* b, int64_t length) override {
		// Round 1: send (g, h) = (g_sigma^r, h_sigma^r) per OT instance.
		// r_i is needed across rounds (used to recover x_sigma in round
		// 2), so keep all r_i live in an array.
		std::vector<BigInt> rs(length);
		for (int64_t i = 0; i < length; ++i) {
			G->get_rand_bn(rs[i]);
			int sigma = b[i] ? 1 : 0;
			const Point &g_base = (sigma == 0 ? g0 : g1);
			const Point &h_base = (sigma == 0 ? h0 : h1);
			Point g_send = g_base.mul(rs[i]);
			Point h_send = h_base.mul(rs[i]);
			io->send_pt(&g_send);
			io->send_pt(&h_send);
		}
		io->flush();

		// Round 2: receive (u_b, c_b) for each b, plus ciphertexts.
		// Recover x_sigma = c_sigma / u_sigma^r and decrypt ct_sigma.
		for (int64_t i = 0; i < length; ++i) {
			int sigma = b[i] ? 1 : 0;
			Point u[2], c_pt[2];
			for (int bb = 0; bb < 2; ++bb) {
				io->recv_pt(G, &u[bb]);
				io->recv_pt(G, &c_pt[bb]);
			}
			block ct[2];
			io->recv_data(ct, 2 * sizeof(block));

			// Additive EC notation: x_sigma = c_sigma - (r · u_sigma).
			// Multiplicative: x_sigma = c_sigma / u_sigma^r.
			Point u_r = u[sigma].mul(rs[i]);
			Point x_sigma = c_pt[sigma].add(u_r.inv());

			data[i] = Hash::KDF(x_sigma, i) ^ ct[sigma];
		}
	}
};

}  // namespace emp
#endif
