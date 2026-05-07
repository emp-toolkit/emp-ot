#ifndef EMP_OTCO_H__
#define EMP_OTCO_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/ot.h"
#include <vector>
namespace emp {

/*
 * Chou Orlandi OT
 * [REF] Implementation of "The Simplest Protocol for Oblivious Transfer"
 * https://eprint.iacr.org/2015/267.pdf
 *
 * Semi-honest only: the simple two-message CO transcript has known
 * malicious-receiver attacks (Genc et al., eprint 2017/596) — the
 * patched UC variant requires extra messages that this implementation
 * doesn't carry. Use OTPVW / OTCSW / OTPVWKyber for malicious-secure
 * base OTs.
 */
class OTCO: public OT { public:
	bool is_malicious_secure() const override { return false; }
	IOChannel* io;
	Group *G = nullptr;
	bool delete_G = true;
	OTCO(IOChannel* io, Group * _G = nullptr) {
		this->io = io;
		if (_G == nullptr)
			G = new Group();
		else {
			G = _G;
			delete_G = false;
		}
	}
	~OTCO() {
		if (delete_G)
			delete G;
	}

	void send(const block* data0, const block* data1, int64_t length) override {
		BigInt a;
		Point A, AaInv;
		block res[2];
		std::vector<Point> B(length);
		std::vector<Point> BA(length);

		G->get_rand_bn(a);
		A = G->mul_gen(a);
		io->send_pt(&A);
		AaInv = A.mul(a);
		AaInv = AaInv.inv();

		for(int64_t i = 0; i < length; ++i) {
			io->recv_pt(G, &B[i]);
			B[i] = B[i].mul(a);
			BA[i] = B[i].add(AaInv);
		}

		for(int64_t i = 0; i < length; ++i) {
			res[0] = Hash::KDF(B[i], i) ^ data0[i];
			res[1] = Hash::KDF(BA[i], i) ^ data1[i];
			io->send_data(res, 2*sizeof(block));
		}
		io->flush();
	}

	void recv(block* data, const bool* b, int64_t length) override {
		std::vector<BigInt> bb(length);
		std::vector<Point> B(length);
		std::vector<Point> As(length);
		Point A;

		for(int64_t i = 0; i < length; ++i)
			G->get_rand_bn(bb[i]);

		io->recv_pt(G, &A);

		for(int64_t i = 0; i < length; ++i) {
			B[i] = G->mul_gen(bb[i]);
			if (b[i])
				B[i] = B[i].add(A);
			io->send_pt(&B[i]);
		}
		io->flush();

		for(int64_t i = 0; i < length; ++i)
			As[i] = A.mul(bb[i]);

		block res[2];
		for(int64_t i = 0; i < length; ++i) {
			io->recv_data(res, 2*sizeof(block));
			data[i] = Hash::KDF(As[i], i);
			if(b[i])
				data[i] = data[i] ^ res[1];
			else
				data[i] = data[i] ^ res[0];
		}
	}
};

}//namespace
#endif// OT_CO_H__
