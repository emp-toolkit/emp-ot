#ifndef OT_SH_EXTENSION_H__
#define OT_SH_EXTENSION_H__
#include "ot.h"
#include "ot_extension.h"
#include "np.h"
/** @addtogroup OT
  @{
 */

template<typename IO>
class SHOTExtension: public OTExtension<IO, OTNP, ::SHOTExtension>{ public:
	SHOTExtension(IO * io) : OTExtension<IO, OTNP, ::SHOTExtension>(io){
	}

	using OTExtension<IO, OTNP, ::SHOTExtension>::send_pre;
	using OTExtension<IO, OTNP, ::SHOTExtension>::recv_pre;

	void send_impl(const block* data0, const block* data1, int length) {
		send_pre(length);
		OTExtension<IO, OTNP, ::SHOTExtension>::got_send_post(data0, data1, length);
	}

	void recv_impl(block* data, const bool* b, int length) {
		recv_pre(b, length);
		OTExtension<IO, OTNP, ::SHOTExtension>::got_recv_post(data, b, length);
	}

	void send_cot(block * data0, block delta, int length) {
		send_pre(length);
		OTExtension<IO, OTNP, ::SHOTExtension>::cot_send_post(data0, delta, length);
	}
	void recv_cot(block* data, const bool* b, int length) {
		recv_pre(b, length);
		OTExtension<IO, OTNP, ::SHOTExtension>::cot_recv_post(data, b, length);
	}
	void send_rot(block * data0, block * data1, int length) {
		send_pre(length);
		OTExtension<IO, OTNP, ::SHOTExtension>::rot_send_post(data0, data1, length);
	}
	void recv_rot(block* data, const bool* b, int length) {
		recv_pre(b, length);
		OTExtension<IO, OTNP, ::SHOTExtension>::rot_recv_post(data, b, length);
	}
};
/**@}*/
#endif// OT_EXTENSION_H__
