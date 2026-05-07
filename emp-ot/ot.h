#ifndef EMP_OT_H__
#define EMP_OT_H__
#include <emp-tool/emp-tool.h>

namespace emp {

class OT { public:
	virtual void send(const block* data0, const block* data1, int64_t length) = 0;
	virtual void recv(block* data, const bool* b, int64_t length)  = 0;
	virtual ~OT() {
	}

	// Static security level of the protocol. Base OTs override to true
	// when malicious-secure (OTPVW / OTCSW / OTPVWKyber) and false
	// otherwise (OTCO). Used by extensions (IKNP / SoftSpokenOT /
	// FerretCOT) to verify at runtime that their own malicious mode
	// is paired with a malicious-secure base OT. Default returns false
	// — safest for any unannotated subclass.
	virtual bool is_malicious_secure() const { return false; }
};

}
#endif
