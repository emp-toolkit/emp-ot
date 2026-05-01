#ifndef EMP_COT_H__
#define EMP_COT_H__
#include "emp-ot/ot.h"

namespace emp {

const static int64_t ot_bsize = 8;
template<typename T>
class COT : public OT<T> {
public:
	block Delta;     // sender's correlation; exposed for test / check code
	virtual void send_cot(block* data0, int64_t length) = 0;
	virtual void recv_cot(block* data, const bool* b, int64_t length) = 0;

protected:
	T * io = nullptr;
	MITCCRH<ot_bsize> mitccrh;
	PRG prg;

public:
	void send(const block* data0, const block* data1, int64_t length) override {
		block * data = new block[length];
		send_cot(data, length);
		block s;prg.random_block(&s, 1);
		io->send_block(&s,1);
		mitccrh.setS(s);
		io->flush();
		block pad[2*ot_bsize];
		for(int64_t i = 0; i < length; i+=ot_bsize) {
			for(int64_t j = i; j < std::min(i+ot_bsize, length); ++j) {
				pad[2*(j-i)] = data[j];
				pad[2*(j-i)+1] = data[j] ^ Delta;
			}
			mitccrh.hash<ot_bsize, 2>(pad);
			for(int64_t j = i; j < std::min(i+ot_bsize, length); ++j) {
				pad[2*(j-i)] = pad[2*(j-i)] ^ data0[j];
				pad[2*(j-i)+1] = pad[2*(j-i)+1] ^ data1[j];
			}
			io->send_data(pad, 2*sizeof(block)*std::min(ot_bsize,length-i));
		}
		delete[] data;
	}

	void recv(block* data, const bool* r, int64_t length) override {
		recv_cot(data, r, length);
		block s;
		io->recv_block(&s,1);
		mitccrh.setS(s);
		io->flush();

		block res[2*ot_bsize];
		block pad[ot_bsize];
		for(int64_t i = 0; i < length; i+=ot_bsize) {
			memcpy(pad, data+i, std::min(ot_bsize,length-i)*sizeof(block));
			mitccrh.hash<ot_bsize, 1>(pad);
			io->recv_data(res, 2*sizeof(block)*std::min(ot_bsize,length-i));
			for(int64_t j = 0; j < ot_bsize and j < length-i; ++j) {
				data[i+j] = res[2*j+r[i+j]] ^ pad[j];
			}
		}
	}

	void send_rot(block* data0, block* data1, int64_t length) {
		send_cot(data0, length);
		block s; prg.random_block(&s, 1);
		io->send_block(&s,1);
		mitccrh.setS(s);
		io->flush();

		block pad[ot_bsize*2];
		for(int64_t i = 0; i < length; i+=ot_bsize) {
			for(int64_t j = i; j < std::min(i+ot_bsize, length); ++j) {
				pad[2*(j-i)] = data0[j];
				pad[2*(j-i)+1] = data0[j] ^ Delta;
			}
			mitccrh.hash<ot_bsize, 2>(pad);
			for(int64_t j = i; j < std::min(i+ot_bsize, length); ++j) {
				data0[j] = pad[2*(j-i)];
				data1[j] = pad[2*(j-i)+1];
			}
		}
	}

	void recv_rot(block* data, const bool* r, int64_t length) {
		recv_cot(data, r, length);
		block s;
		io->recv_block(&s,1);
		mitccrh.setS(s);
		io->flush();
		block pad[ot_bsize];
		for(int64_t i = 0; i < length; i+=ot_bsize) {
			memcpy(pad, data+i, std::min(ot_bsize,length-i)*sizeof(block));
			mitccrh.hash<ot_bsize, 1>(pad);
			memcpy(data+i, pad, std::min(ot_bsize,length-i)*sizeof(block));
		}
	}
};

template<typename T>
class RandomCOT : public COT<T> {
public:
	// Role-specific random COT generation. Concrete backends supply both
	// — the role is implicit in which method runs, so no party flag is
	// needed at this layer for dispatch.
	virtual void rcot_send(block* data, int64_t num) = 0;
	virtual void rcot_recv(block* data, int64_t num) = 0;

	void send_cot(block* data, int64_t length) override {
		rcot_send(data, length);
		bool* bo = new bool[length];
		this->io->recv_bool(bo, length * sizeof(bool));
		for (int64_t i = 0; i < length; ++i) {
			if (bo[i]) data[i] = data[i] ^ this->Delta;
		}
		delete[] bo;
	}

	void recv_cot(block* data, const bool* b, int64_t length) override {
		rcot_recv(data, length);
		bool* bo = new bool[length];
		for (int64_t i = 0; i < length; ++i) {
			bo[i] = b[i] ^ getLSB(data[i]);
		}
		this->io->send_bool(bo, length * sizeof(bool));
		delete[] bo;
	}
};
}
#endif
