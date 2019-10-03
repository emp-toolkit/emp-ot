#ifndef OT_CO_H__
#define OT_CO_H__
#include "emp-ot/ot.h"
#include <emp-tool/emp-tool.h>
/** @addtogroup OT
    @{
  */
namespace emp {
template<typename IO>
class OTCO: public OT<OTCO<IO>> { public:
	IO* io;
	Group *G = nullptr;
	bool delete_G = true;
	OTCO(IO* io, Group * _G = nullptr) {
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

	void send_impl(const block* data0, const block* data1, int length) {
		BigInt a;
		Point A, AaInv;
		block res[2];
		Point * B = new Point[length];
		Point * BA = new Point[length];
		for (int i = 0; i < length; ++i) {
			B[i] = Point(G);
			BA[i] = Point(G);
		}

		G->get_rand_bn(a);
		A = G->mul_gen(a);//g^a
		AaInv = A.mul(a);//g^(a^2)
		AaInv = AaInv.inv();//g^(-a^2)
		io->send_pt(&A);

		for(int i = 0; i < length; ++i) {
			io->recv_pt(&B[i]);
			B[i] = B[i].mul(a);
			BA[i] = B[i].add(AaInv);
		}

		for(int i = 0; i < length; ++i) {
			res[0] = Hash::KDF(B[i], i);
			res[1] = Hash::KDF(BA[i], i);
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
		Point * As = new Point[length];
		Point A(G);
		for(int i = 0; i < length; ++i) {
			G->get_rand_bn(bb[i]);
			B[i] = G->mul_gen(bb[i]);
			As[i] = Point(G);
		}

		io->recv_pt(&A);
		for(int i = 0; i < length; ++i)
			if (b[i]) 
				B[i] = B[i].add(A);

		for (int i = 0; i < length; ++i)
			io->send_pt(&B[i]);

		for(int i = 0; i < length; ++i)
			As[i] = A.mul(bb[i]);

		block res[2];
		for(int i = 0; i < length; ++i) {
			io->recv_data(res, 2*sizeof(block));
			data[i] = Hash::KDF(As[i], i);
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
