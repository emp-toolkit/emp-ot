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
	IO* io;
	Group *G;
	OTCO(IO* io, Group * _G = nullptr) {
		this->io = io;
		if (_G == nullptr)
			G = new Group();
		else
			G = _G;
	}

	void send_impl(const block* data0, const block* data1, int length) {
		BigInt a;
		Point A, AaInv;
		Point * B = new Point[length];
		Point * BA = new Point[length];

		G->get_rand_bn(a);
		G->init(A);
		G->init(AaInv);
		for(int i = 0; i < length; ++i) {
			G->init(B[i]);
			G->init(BA[i]);
		}
		
		block res[2];
		G->mul_gen(A, a);
		G->mul(AaInv, A, a);
		G->inv(AaInv, AaInv);
		io->send_pt(G, &A);

		for(int i = 0; i < length; ++i) {
			io->recv_pt(G, B + i);
			G->mul(B[i], B[i], a);
			G->add(BA[i], B[i], AaInv);
		}

		for(int i = 0; i < length; ++i) {
			res[0] = Hash::KDF(G, B[i], i);
			res[1] = Hash::KDF(G, BA[i], i);
			res[0] = xorBlocks(res[0], data0[i]);
			res[1] = xorBlocks(res[1], data1[i]);

			io->send_data(res, 2*sizeof(block));
		}

		delete[] BA;
		delete[] B;
	}

	void recv_impl(block* data, const bool* b, int length) {
		BigInt * bb = new BigInt[length];
		Point * B = new Point[length];
		Point A;
		G->init(A);
		for(int i = 0; i < length; ++i) {
			G->init(B[i]);
			G->get_rand_bn(bb[i]);
			G->mul_gen(B[i], bb[i]);
		}

		io->recv_pt(G, &A);
		for(int i = 0; i < length; ++i)
			if (b[i]) 
				G->add(B[i], A, B[i]);

		io->send_pt(G, B, length);io->flush();
		for(int i = 0; i < length; ++i)
			G->mul(A, A, bb[i]);

		block res[2];
		for(int i = 0; i < length; ++i) {
			io->recv_data(res, 2*sizeof(block));
			data[i] = Hash::KDF(G, A, i);
			if(b[i])
				data[i] = xorBlocks(data[i], res[1]);
			else
				data[i] = xorBlocks(data[i], res[0]);
	}
		
	delete[] bb;
	delete[] B;
	}
};
  /**@}*/
}
#endif// OT_CO_H__
