#ifndef OT_IDEAL_H__
#define OT_IDEAL_H__
#include "ot.h"
void ot_ideal_send(OT* ot, const block* data0, const block* data1, int length);
void ot_ideal_recv(OT* ot, block* data, const bool* b, int length);

class OTIdeal: public OT {
public:
	int cnt;
	OTIdeal(NetIO * io): OT(io) {
		type = IDEAL_OT;
		cnt = 0;
		send_internal = ot_ideal_send;
		recv_internal = ot_ideal_recv;
	}

	~OTIdeal() {
	}
};


void ot_ideal_send(OT* ot, const block* data0, const block* data1, int length) {
	ot->io->send_block(data0, length);
	ot->io->send_block(data1, length);
}

void ot_ideal_recv(OT* ot, block* data, const bool* b, int length) {
	block *data1 = new block[length];
	ot->io->recv_block(data, length);
	ot->io->recv_block(data1, length);
	for(int i = 0; i < length; ++i)
		if(b[i])
			data[i] = data1[i];
	delete []data1;
}
#endif// OT_IDEAL_H__