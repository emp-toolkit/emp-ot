#ifndef EMP_FERRET_CONSTANTS_H__
#define EMP_FERRET_CONSTANTS_H__

namespace emp { 
static std::string PRE_OT_DATA_REG_SEND_FILE = "./data/pre_ot_data_reg_send";
static std::string PRE_OT_DATA_REG_RECV_FILE = "./data/pre_ot_data_reg_recv";

class PrimalLPNParameter { public:
	int64_t n, t, k, log_bin_sz, n_pre, t_pre, k_pre, log_bin_sz_pre;
	PrimalLPNParameter() {}
	PrimalLPNParameter(int64_t n, int64_t t, int64_t k, int64_t log_bin_sz, int64_t n_pre, int64_t t_pre, int64_t k_pre, int64_t log_bin_sz_pre)
		: n(n), t(t), k(k), log_bin_sz(log_bin_sz),
		n_pre(n_pre), t_pre(t_pre), k_pre(k_pre), log_bin_sz_pre(log_bin_sz_pre) {

		if(n != t * (1<<log_bin_sz) ||
			n_pre != t_pre * (1<< log_bin_sz_pre) ||
			n_pre < k + t * log_bin_sz + 128 )
			error("LPN parameter not matched");	
	}
	int64_t buf_sz() const {
		return n - t * log_bin_sz - k - 128;
	}
};

const static PrimalLPNParameter ferret_b13 = PrimalLPNParameter(10485760, 1280, 452000, 13, 470016, 918, 32768, 9);
const static PrimalLPNParameter ferret_b12 = PrimalLPNParameter(10268672, 2507, 238000, 12, 268800, 1050, 17384, 8);
const static PrimalLPNParameter ferret_b11 = PrimalLPNParameter(10180608, 4971, 124000, 11, 178944, 699, 17384, 8);

}//namespace
#endif //EMP_FERRET_CONSTANTS_H__
