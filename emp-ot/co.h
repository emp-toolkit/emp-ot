#ifndef OT_CO_H__
#define OT_CO_H__
#include "emp-ot/ot.h"
#include "emp-tool/utils/constants.h" // gTbl::tbl
/** @addtogroup OT
    @{
  */
namespace emp {
template<typename IO>
class OTCO: public OT<OTCO<IO>> { public:
	int cnt;
	eb_t g;
	bn_t q;
	PRG prg;
	IO* io;
	OTCO(IO* io) {
		this->io = io;
        gTbl::init();
		eb_curve_get_gen(g);
		eb_curve_get_ord(q);
    }

	void send_impl(const block* data0, const block* data1, int length) {
		bn_t * a = new bn_t[length];
		eb_t * B = new eb_t[length];
		eb_t * A = new eb_t[length];
		for(int i = 0; i < length; ++i) {
			eb_newl(A[i], B[i]);
			bn_newl(a[i]);
		}

		block res[2];
		prg.random_bn(a, length);
		for(int i = 0; i < length; ++i) {
			eb_mul_fix_norm(A[i], gTbl::tbl, a[i]);
			io->send_eb(&A[i], 1);
		}

		for(int i = 0; i < length; ++i) {
			io->recv_eb(&B[i], 1);
			eb_mul_norm(B[i], B[i], a[i]);
			bn_sqr(a[i], a[i]);
			bn_mod(a[i], a[i], q);
			eb_mul_fix_norm(A[i], gTbl::tbl, a[i]);
			eb_sub_norm(A[i], B[i], A[i]);
		}

		for(int i = 0; i < length; ++i){
			res[0] = KDF(B[i]);	
			res[1] = KDF(A[i]);
			res[0] = xorBlocks(res[0], data0[i]);
			res[1] = xorBlocks(res[1], data1[i]);

			io->send_data(res, 2*sizeof(block));
		}

		for(int i = 0; i < length; ++i) {
			eb_freel(A[i], B[i]);
			bn_freel(a[i]);
		}
		delete[] a;
		delete[] A;
		delete[] B;
	}

	void recv_impl(block* data, const bool* b, int length) {
		bn_t * bb = new bn_t[length];
		eb_t * B = new eb_t[length];
		eb_t * A = new eb_t[length];
		for(int i = 0; i < length; ++i) {
			eb_newl(A[i], B[i]);
			bn_newl(bb[i]);
		}
		prg.random_bn(bb, length);

		for(int i = 0; i < length; ++i) {
			eb_mul_fix_norm(B[i], gTbl::tbl, bb[i]);
			io->recv_eb(&A[i], 1);
			if (b[i]) {
				eb_add_norm(B[i], A[i], B[i]);
			}
		}

		io->send_eb(B, length);
		for(int i = 0; i < length; ++i) {
			eb_mul_norm(A[i], A[i], bb[i]);
		}

		block res[2];
		for(int i = 0; i < length; ++i) {
			io->recv_data(res, 2*sizeof(block));
			data[i] = KDF(A[i]);
			if(b[i])
				data[i] = xorBlocks(data[i], res[1]);
			else
				data[i] = xorBlocks(data[i], res[0]);
		}
		for(int i = 0; i < length; ++i) {
			eb_freel(A[i], B[i]);
			bn_freel(bb[i]);
		}
		delete[] bb;
		delete[] A;
		delete[] B;
	}
};
  /**@}*/
}
#endif// OT_CO_H__
