#ifndef OT_CO_H__
#define OT_CO_H__
#include "emp-ot/ot.h"
#include "emp-tool/ec_group/group.h"
/** @addtogroup OT
    @{
  */
namespace emp {
template<typename IO>
class OTCO: public OT<OTCO<IO>> { 
private:

	void send_point(const Point &A)
	{
		char *data = G.to_hex(A);
		int len = strlen(data);
		io->send_data(&len, 4);
		io->send_data(data, len);
	}

	void recv_point(Point &A)
	{

		int len;
		char *data;
		io->recv_data(&len, 4);
		data = new char[len + 1];
		data[len] = 0;
		io->recv_data(data, len);
		G.from_hex(A, data);
	}	

	block KDF(Point &in) {
		char* tmp=G.to_hex(in);
		return Hash::hash_for_block(tmp, strlen(tmp));
	}
public:
	//int cnt;
	//eb_t g;
	//bn_t q;
	//eb_t gTbl[RLC_EB_TABLE_MAX];
	//PRG prg;


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
			a[i].rand_mod(order);
		}


		block res[2];
		//prg.random_bn(a, length);
		for(int i = 0; i < length; ++i) {
			//eb_mul_fix_norm(A[i], gTbl, a[i]);
			G.mul_gen(A[i],a[i]);
			send_point(A[i]);
		}

		
		for(int i = 0; i < length; ++i) {
			//io->recv_eb(&B[i], 1);
			recv_point(B[i]);

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
			
			res[0] = KDF(B[i]);	
			res[1] = KDF(A[i]);
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
			bb[i].rand_mod(order);
		}
		//prg.random_bn(bb, length);

		for(int i = 0; i < length; ++i) {
			//eb_mul_fix_norm(B[i], gTbl, bb[i]);
			recv_point(A[i]);
			if (b[i]) {
				//eb_add_norm(B[i], A[i], B[i]);
				G.add(B[i],A[i],B[i]);
			}
		}

		for(int i = 0; i < length; ++i) 
			send_point(B[i]);
		for(int i = 0; i < length; ++i) {
			//eb_mul_norm(A[i], A[i], bb[i]);
			G.mul(A[i],A[i],bb[i]);
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
		
		delete[] bb;
		delete[] A;
		delete[] B;
	}
};
  /**@}*/
}
#endif// OT_CO_H__