#ifndef EMP_OTIDEAL_H__
#define EMP_OTIDEAL_H__
#include "emp-ot/ot.h"

namespace emp { 
template<typename IO> 
class OTIdeal: public OT<IO> { public:
	int cnt = 0;
	IO* io = nullptr;
	OTIdeal(IO * io) {
		this->io = io;
	}

	void send(const block* data0, const block* data1, int length) override {
		cnt+=length;
		io->send_block(data0, length);
		io->send_block(data1, length);
	}

	void recv(block* data, const bool* b, int length) override {
		cnt+=length;
		block *data1 = new block[length];
		io->recv_block(data, length);
		io->recv_block(data1, length);
		for(int i = 0; i < length; ++i)
			if(b[i])
				data[i] = data1[i];
		delete []data1;
	}
};
}//namespace
#endif// OT_IDEAL_H__
