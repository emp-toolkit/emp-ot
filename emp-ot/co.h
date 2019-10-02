#ifndef OT_CO_H__
#define OT_CO_H__
#include "emp-ot/ot.h"
#include <emp-tool/emp-tool.h>
/** @addtogroup OT
    @{
  */
namespace emp {
template<typename IO>
class OTCO: public OT<OTCO<IO>> { 

public:
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
	}

	void send_impl(const block* data0, const block* data1, int length) {
		
		BigInt * a = new BigInt[length];
		Point * B = new Point[length];
		Point * A = new Point[length];

		for(int i = 0; i < length; ++i) {
			G.init(A[i]);
			G.init(B[i]);
//			prg.random_bi(a[i]);	
			G.get_rand_bn(a[i]);
			a[i].mod(order);
		}

		block res[2];
		for(int i = 0; i < length; ++i) {
			G.mul_gen(A[i],a[i]);
			io->send_pt(G, A + i);
		}
		
		for(int i = 0; i < length; ++i) {
			io->recv_pt(G,B + i);
			G.mul(B[i], B[i], a[i]);
			G.mul(A[i],A[i],a[i]);
			G.inv(A[i],A[i]);
			G.add(A[i],B[i],A[i]);
		}

		for(int i = 0; i < length; ++i){
			
			res[0] = Hash::KDF(G,B[i]);	
			res[1] = Hash::KDF(G,A[i]);
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
			G.init(A[i]);
			G.init(B[i]);
//			prg.random_bi(bb[i]);	
			G.get_rand_bn(bb[i]);
			bb[i].mod(order);
		}

		for(int i = 0; i < length; ++i) {
			io->recv_pt(G, A + i);
			if (b[i]) {
				G.add(B[i],A[i],B[i]);
			}
		}

		io->send_pt(G, B, length);
		for(int i = 0; i < length; ++i) {
			G.mul(A[i],A[i],bb[i]);
		}

		block res[2];
		for(int i = 0; i < length; ++i) {
			io->recv_data(res, 2*sizeof(block));
			data[i] = Hash::KDF(G,A[i]);
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
