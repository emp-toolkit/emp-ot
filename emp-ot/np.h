#ifndef OT_NP_H__
#define OT_NP_H__
#include "emp-ot/ot.h"
/** @addtogroup OT
	@{
*/
namespace emp {
template<typename IO>
class OTNP: public OT<OTNP<IO>> { public:
	eb_t g, C;
	eb_t gTbl[RLC_EB_TABLE_MAX];
	bn_t q;
	PRG prg;
	IO* io;
	OTNP(IO* io) {
		this->io = io;
		initialize_relic();
		eb_curve_get_gen(g);
		eb_curve_get_ord(q);
		MemIO mio;
		char * tmp = mio.buffer;
		mio.buffer = (char*)eb_curve_get_tab_data;
		mio.size = 15400*8;
		mio.recv_eb(gTbl, RLC_EB_TABLE_MAX);
		eb_new(C);
		mio.buffer = tmp;
	}

	void send_impl(const block* data0, const block* data1, int length) {
		bn_t d; bn_new(d); prg.random_bn(d);
		eb_mul_fix_norm(C, gTbl, d);
		io->send_eb(&C, 1);io->flush();

		bn_t *r = new bn_t[length], *rc = new bn_t[length];
		eb_t *pk0 = new eb_t[length], pk1, 
			  *gr = new eb_t[length], *Cr = new eb_t[length];
		eb_newl(pk1);
		for(int i = 0; i < length; ++i) {
			eb_newl(gr[i], Cr[i], pk0[i]);
			bn_newl(r[i], rc[i]);
			prg.random_bn(r[i]);
			eb_mul_fix_norm(gr[i], gTbl, r[i]);
			bn_mul(rc[i], r[i], d);
			bn_mod(rc[i], rc[i], q);
			eb_mul_fix_norm(Cr[i], gTbl, rc[i]);
		}

		for(int i = 0; i < length; ++i) {
			io->recv_eb(&pk0[i], 1);
		}
		for(int i = 0; i < length; ++i) {
			io->send_eb(&gr[i], 1);
		}
		io->flush();

		block m[2];
		for(int i = 0 ; i < length; ++i) {
			eb_mul_norm(pk0[i], pk0[i], r[i]);
			eb_sub_norm(pk1, Cr[i], pk0[i]);
			m[0] = KDF(pk0[i]);
			m[0] = xorBlocks(data0[i], m[0]);
			m[1] = KDF(pk1);
	       		m[1] = xorBlocks(data1[i], m[1]);
			io->send_data(m, 2*sizeof(block));
		}

		eb_freel(pk1);
		for(int i =0; i < length; ++i) {
			eb_freel(gr[i], Cr[i], pk0[i]);
			bn_freel(r[i], rc[i]);
		}
		delete[] r;
		delete[] gr;
		delete[] Cr;
		delete[] rc;
		delete[] pk0;
	}

	void recv_impl(block* data, const bool* b, int length) {
		bn_t * k = new bn_t[length];
		eb_t * gr = new eb_t[length];
		eb_t pk[2];
		block m[2];
		eb_newl(pk[0], pk[1]);
		for(int i = 0; i < length; ++i) {
			bn_newl(k[i]);
			eb_newl(gr[i]);
		}
		prg.random_bn(k, length);
		io->recv_eb(&C, 1);

		for(int i = 0; i< length; ++i) {
			if(b[i]) {
				eb_mul_fix_norm(pk[1], gTbl, k[i]);
				eb_sub_norm(pk[0], C, pk[1]);
			} else {
				eb_mul_fix_norm(pk[0], gTbl, k[i]);
			}
			io->send_eb(&pk[0], 1);
		}

		for(int i = 0; i < length; ++i) {
			io->recv_eb(&gr[i], 1);
			eb_mul_norm(gr[i], gr[i], k[i]);
		}
		for(int i = 0; i < length; ++i) {
			int ind = b[i] ? 1 : 0;
			io->recv_data(m, 2*sizeof(block));
			data[i] = xorBlocks(m[ind], KDF(gr[i]));
		}
		for(int i = 0; i < length; ++i) {
			bn_freel(k[i]);
			eb_freel(gr[i]);
		}
		eb_freel(pk[0], pk[1]);
		delete[] k;
		delete[] gr;
	}

};
/**@}*/
}
#endif// OT_NP_H__
