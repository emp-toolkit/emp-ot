#ifndef OT_CO_H__
#define OT_CO_H__
#include "emp-ot/ot.h"
#include "emp-tool/ec_group/group.h"
#include "emp-tool/utils/utils_ec.h"
/** @addtogroup OT
    @{
  */
namespace emp {
template<typename IO>
class OTCO: public OT<OTCO<IO>> { 

public:
	//int cnt;
	//eb_t g;
	//bn_t q;
	//eb_t gTbl[RLC_EB_TABLE_MAX];
	PRG prg;


	IO* io;
	Group G;
	BigInt order;
	Point g;
	OTCO(IO* io) {
		this->io = io;
		G.get_order(order);
		G.init(g);
		G.get_generator(g);
		/*initialize_relic();
		eb_curve_get_gen(g);
		eb_curve_get_ord(q);
		MemIO mio;
		char * tmp = mio.buffer;
		mio.buffer = (char*)eb_curve_get_tab_data;
		mio.size = 15400*8;
		mio.recv_eb(gTbl, RLC_EB_TABLE_MAX);
		eb_new(C);
		mio.buffer = tmp;*/
	}

	void send_impl(const block* data0, const block* data1, int length) {
		
		BigInt * a = new BigInt[length];
		Point * B = new Point[length];
		Point * A = new Point[length];

		for(int i = 0; i < length; ++i) {
			//eb_newl(A[i], B[i]);
			//bn_newl(a[i]);
			G.init(A[i]);
			G.init(B[i]);
			prg.random_bi(a[i]);	
			a[i].mod(order);
		}


		block res[2];
		//prg.random_bn(a, length);
		for(int i = 0; i < length; ++i) {
			//eb_mul_fix_norm(A[i], gTbl, a[i]);
			G.mul_gen(A[i],a[i]);
			io->send_pt(G,A[i]);
		}

		
		for(int i = 0; i < length; ++i) {
			//io->recv_eb(&B[i], 1);
			io->recv_pt(G,B[i]);

			//eb_mul_norm(B[i], B[i], a[i]);
			//bn_sqr(a[i], a[i]);
			//bn_mod(a[i], a[i], q);
			//eb_mul_fix_norm(A[i], gTbl, a[i]);
			//eb_sub_norm(A[i], B[i], A[i]);
			
			G.mul(B[i], B[i], a[i]);
			G.mul(A[i],A[i],a[i]);
			G.inv(A[i],A[i]);
			G.add(A[i],B[i],A[i]);

			
		}
		for(int i = 0; i < length; ++i){
			
			res[0] = KDF_pt(G,B[i]);	
			res[1] = KDF_pt(G,A[i]);
			res[0] = xorBlocks(res[0], data0[i]);
			res[1] = xorBlocks(res[1], data1[i]);

			io->send_data(res, 2*sizeof(block));
		}

		delete[] a;
		delete[] A;
		delete[] B;
	}

	void recv_impl(block* data, const bool* b, int length) {
		BigInt * bb = new BigInt[length];
		Point * B = new Point[length];
		Point * A = new Point[length];
		for(int i = 0; i < length; ++i) {
			//eb_newl(A[i], B[i]);
			//bn_newl(bb[i]);
			G.init(A[i]);
			G.init(B[i]);
			prg.random_bi(bb[i]);	
			bb[i].mod(order);
		}
		//prg.random_bn(bb, length);

		for(int i = 0; i < length; ++i) {
			//eb_mul_fix_norm(B[i], gTbl, bb[i]);
			io->recv_pt(G,A[i]);
			if (b[i]) {
				//eb_add_norm(B[i], A[i], B[i]);
				G.add(B[i],A[i],B[i]);
			}
		}

		for(int i = 0; i < length; ++i) 
			io->send_pt(G,B[i]);
		for(int i = 0; i < length; ++i) {
			//eb_mul_norm(A[i], A[i], bb[i]);
			G.mul(A[i],A[i],bb[i]);
		}

		block res[2];
		for(int i = 0; i < length; ++i) {
			io->recv_data(res, 2*sizeof(block));
			data[i] = KDF_pt(G,A[i]);
			if(b[i])
				data[i] = xorBlocks(data[i], res[1]);
			else
				data[i] = xorBlocks(data[i], res[0]);
		}
		
		delete[] bb;
		delete[] A;
		delete[] B;
	}
};
  /**@}*/
}
#endif// OT_CO_H__
