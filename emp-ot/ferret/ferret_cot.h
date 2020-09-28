#ifndef EMP_FERRET_COT_H_
#define EMP_FERRET_COT_H_
#include "emp-ot/ferret/mpcot_reg.h"
#include "emp-ot/ferret/base_cot.h"
#include "emp-ot/ferret/lpn_f2.h"
#include "emp-ot/ferret/constants.h"

namespace emp {

/*
 * Ferret COT binary version
 * [REF] Implementation of "Ferret: Fast Extension for coRRElated oT with small communication"
 * https://eprint.iacr.org/2020/924.pdf
 *
 */
template<typename T, int threads>
class FerretCOT: public COT<T> { 
public:
	using COT<T>::io;
	using COT<T>::Delta;

	int n, t, k, log_bin_sz;
	int n_pre, t_pre, k_pre, log_bin_sz_pre;
	int ot_used, ot_limit;

	FerretCOT(int party, T * ios[threads+1], bool malicious = false, bool run_setup = true, std::string pre_file="");

	~FerretCOT();

	void setup(block Deltain, std::string pre_file = "");

	void setup(std::string pre_file = "");

	void send_cot(block * data, int length) override;

	void recv_cot(block* data, const bool * b, int length) override;

	void rcot(block *data, int num);

	uint64_t rcot_inplace(block *ot_buffer, int length);

	uint64_t byte_memory_need_inplace(uint64_t ot_need);

private:
	block ch[2];

	NetIO **ios;
	int party;
	int M;
	bool is_malicious;
	bool extend_initialized;

	block one;

	block * ot_pre_data = nullptr;
	block * ot_data = nullptr;

	std::string pre_ot_filename;

	BaseCot *base_cot = nullptr;
	OTPre<NetIO> *pre_ot = nullptr;
	ThreadPool *pool = nullptr;
	MpcotReg<threads> *mpcot = nullptr;
	LpnF2<10> *lpn_f2 = nullptr;

	
	void online_sender(block *data, int length);

	void online_recver(block *data, const bool *b, int length);

	void set_param();

	void set_preprocessing_param();

	void extend_initialization();

	void extend(block* ot_output, MpcotReg<threads> *mpfss, OTPre<NetIO> *preot, 
			LpnF2<10> *lpn, block *ot_input);

	void extend_f2k(block *ot_buffer);

	void extend_f2k();

	int silent_ot_left();

	void write_pre_data128_to_file(void* loc, __uint128_t delta, std::string filename);

	__uint128_t read_pre_data128_from_file(void* pre_loc, std::string filename);
};

#include "emp-ot/ferret/ferret_cot.hpp"
}
#endif// _VOLE_H_
