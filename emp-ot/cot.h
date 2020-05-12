#ifndef EMP_COT_H__
#define EMP_COT_H__
#include "emp-ot/ot.h"

namespace emp {

const static int ot_bsize = 8;
template<typename T>
class COT : public OT<T>{ public:
	T * io = nullptr;
	MITCCRH<ot_bsize> mitccrh;
	block Delta;
	virtual void send_cot(block* data0, int length) = 0;
	virtual void recv_cot(block* data, const bool* b, int length) = 0;
	void send(const block* data0, const block* data1, int length) override {
		block * data = new block[length];
		send_cot(data, length);
		mitccrh.setS(zero_block);
		io->flush();
		block pad[2*ot_bsize];
		for(int i = 0; i < length; i+=ot_bsize) {
			for(int j = i; j < i+ot_bsize and j < length; ++j) {
				pad[2*(j-i)] = data[j];
				pad[2*(j-i)+1] = data[j] ^ Delta;
			}
			mitccrh.hash<ot_bsize, 2>(pad);
			for(int j = i; j < i+ot_bsize and j < length; ++j) {
				pad[2*(j-i)] = pad[2*(j-i)] ^ data0[j];
				pad[2*(j-i)+1] = pad[2*(j-i)+1] ^ data1[j];
			}
			io->send_data(pad, 2*sizeof(block)*min(ot_bsize,length-i));
		}
		delete[] data;
	}

	void recv(block* data, const bool* r, int length) override {
		recv_cot(data, r, length);
		mitccrh.setS(zero_block);
		io->flush();

		block res[2*ot_bsize];
		block pad[ot_bsize];
		for(int i = 0; i < length; i+=ot_bsize) {
			memcpy(pad, data+i, min(ot_bsize,length-i)*sizeof(block));
			mitccrh.hash<ot_bsize, 1>(pad);
			io->recv_data(res, 2*sizeof(block)*min(ot_bsize,length-i));
			for(int j = 0; j < ot_bsize and j < length-i; ++j) {
				data[i+j] = res[2*j+r[i+j]] ^ pad[j];
			}
		}
	}

	void send_rot(block* data0, block* data1, int length) {
		send_cot(data0, length);
		io->flush();
		block pad[ot_bsize*2];
		for(int i = 0; i < length; i+=ot_bsize) {
			for(int j = i; j < i+ot_bsize and j < length; ++j) {
				pad[2*(j-i)] = data0[j];
				pad[2*(j-i)+1] = data0[j] ^ Delta;
			}
			mitccrh.hash<ot_bsize, 2>(pad);
			for(int j = i; j < i+ot_bsize and j < length; ++j) {
				data0[j] = pad[2*(j-i)];
				data1[j] = pad[2*(j-i)+1];
			}
		}
	}

	void recv_rot(block* data, const bool* r, int length) {
		recv_cot(data, r, length);
		io->flush();
		block pad[ot_bsize];
		for(int i = 0; i < length; i+=ot_bsize) {
			memcpy(pad, data+i, min(ot_bsize,length-i)*sizeof(block));
			mitccrh.hash<ot_bsize, 1>(pad);
			memcpy(data+i, pad, min(ot_bsize,length-i)*sizeof(block));
		}
	}
};
}
#endif