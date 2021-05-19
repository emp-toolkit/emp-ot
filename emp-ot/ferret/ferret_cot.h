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
template<typename T>
class FerretCOT: public COT<T> { 
public:
	using COT<T>::io;
	using COT<T>::Delta;

	size_t n, t, k, log_bin_sz;
	size_t n_pre, t_pre, k_pre, log_bin_sz_pre;
	size_t ot_used, ot_limit;

	FerretCOT(int party, int threads, T **ios, bool malicious = false, bool run_setup = true, std::string pre_file="");

	~FerretCOT();

	void setup(block Deltain, std::string pre_file = "");

	void setup(std::string pre_file = "");

	void send_cot(block * data, size_t length) override;

	void recv_cot(block* data, const bool * b, size_t length) override;

	void rcot(block *data, size_t num);

	size_t rcot_inplace(block *ot_buffer, size_t length);

	size_t byte_memory_need_inplace(size_t ot_need);

	void assemble_state(void * data, size_t size);

	size_t disassemble_state(const void * data, size_t size);

	size_t state_size();
private:
	block ch[2];

	T **ios;
	int party, threads;
	size_t M;
	bool is_malicious;
	bool extend_initialized;

	block one;

	block * ot_pre_data = nullptr;
	block * ot_data = nullptr;

	std::string pre_ot_filename;

	BaseCot<T> *base_cot = nullptr;
	OTPre<T> *pre_ot = nullptr;
	ThreadPool *pool = nullptr;
	MpcotReg<T> *mpcot = nullptr;
	LpnF2<T, 10> *lpn_f2 = nullptr;

	
	void online_sender(block *data, size_t length);

	void online_recver(block *data, const bool *b, size_t length);

	void set_param();

	void set_preprocessing_param();

	void extend_initialization();

	void extend(block* ot_output, MpcotReg<T> *mpfss, OTPre<T> *preot, 
			LpnF2<T, 10> *lpn, block *ot_input);

	void extend_f2k(block *ot_buffer);

	void extend_f2k();

	size_t silent_ot_left();

	void write_pre_data128_to_file(void* loc, __uint128_t delta, std::string filename);

	__uint128_t read_pre_data128_from_file(void* pre_loc, std::string filename);
};

#include "emp-ot/ferret/ferret_cot.hpp"
}
#endif// _VOLE_H_
