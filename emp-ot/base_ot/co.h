#ifndef EMP_CO_H__
#define EMP_CO_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/ot.h"
#include <vector>
namespace emp {

/*
 * Chou Orlandi OT
 * [REF] Implementation of "The Simplest Protocol for Oblivious Transfer"
 * https://eprint.iacr.org/2015/267.pdf
 *
 */
class CO: public OT { public:
	ECGroup G;
	CO(IOChannel* io) { this-> io = io;}

	void send(const block* data0, const block* data1, int64_t length) override {
		expect_ot_args(length, data0, data1,
		               "CO::send: invalid length or null buffer");
		block res[2];
		std::vector<Point> B(length);
		std::vector<Point> BA(length);

		Scalar a = G.rand_scalar();
		Point A = G.mul_gen(a);
		io->send_pt(&A);
		Point AaInv = A.mul(a).inv();

		for(int64_t i = 0; i < length; ++i) {
			io->recv_pt(&G, &B[i]);
			B[i] = B[i].mul(a);
			BA[i] = B[i].add(AaInv);
		}

		for(int64_t i = 0; i < length; ++i) {
			res[0] = RO("emp-ot:co-base-ot:kdf", sid.value()).absorb(B[i]).absorb((uint64_t)i).squeeze_block() ^ data0[i];
			res[1] = RO("emp-ot:co-base-ot:kdf", sid.value()).absorb(BA[i]).absorb((uint64_t)i).squeeze_block() ^ data1[i];
			io->send_data(res, 2*sizeof(block));
		}
		io->flush();
	}

	void recv(block* data, const bool* b, int64_t length) override {
		expect_ot_args(length, data, b,
		               "CO::recv: invalid length or null buffer");
		std::vector<Scalar> bb(length);
		std::vector<Point> B(length);
		std::vector<Point> As(length);
		Point A;

		for(int64_t i = 0; i < length; ++i) {
			bb[i] = G.rand_scalar();
			B[i] = G.mul_gen(bb[i]);
		}

		io->recv_pt(&G, &A);

		for(int64_t i = 0; i < length; ++i) {
			if (b[i])
				B[i] = B[i].add(A);
			io->send_pt(&B[i]);
		}

		for(int64_t i = 0; i < length; ++i)
			As[i] = A.mul(bb[i]);

		block res[2];
		for(int64_t i = 0; i < length; ++i) {
			io->recv_data(res, 2*sizeof(block));
			data[i] = RO("emp-ot:co-base-ot:kdf", sid.value()).absorb(As[i]).absorb((uint64_t)i).squeeze_block() ^ res[b[i]];
		}
	}
};

}//namespace
#endif// OT_CO_H__
