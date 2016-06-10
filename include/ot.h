#ifndef OT_SENDER_H__
#define OT_SENDER_H__
#include <emp-tool/emp-tool.h>

#define IDEAL_OT 1
#define NP_OT 2
#define OT_EXTENSION 5
#define CO_OT 2

class OT {
public:
	OT(NetIO * nio): io(nio){};
	NetIO* io;
	~OT(){
	}
	int type;
	void send(const block* data0, const block* data1, int length) {
		this->send_internal(this, data0, data1, length);
	}
	void recv(block* data, const bool* b, int length) {
		this->recv_internal(this, data, b, length);
	}
	void send(const block* data0, const block* data1) {
		this->send_internal(this, data0, data1, 1);
	}

	void recv(block* data, const bool* b) {
		this->recv_internal(this, data, b, 1);
	}
	void (*send_internal)(OT*ot, const block* data0, const block* data1, int length);
	void (*recv_internal)(OT*ot, block* data, const bool* b, int length);

};
#endif// OT_SENDER_H__
