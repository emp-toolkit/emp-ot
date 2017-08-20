#ifndef OT_H__
#define OT_H__
#include <emp-tool/emp-tool.h>
namespace emp {
template<typename T>
class OT {
public:
	void send(const block* data0, const block* data1, int length) {
		static_cast<T*>(this)->send_impl(data0, data1, length);
	}
	void recv(block* data, const bool* b, int length) {
		static_cast<T*>(this)->recv_impl(data, b, length);
	}
};
}
#endif// OT_H__
