#ifndef EMP_FERRET_COT_H_
#define EMP_FERRET_COT_H_
#include "emp-ot/cot.h"
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
class FerretCOT: public COT {
public:
	PrimalLPNParameter param;
	int64_t ot_used, ot_limit;

	FerretCOT(int party, int threads, IOChannel **ios, bool malicious = false, bool run_setup = true,
			PrimalLPNParameter param = ferret_b13, std::string pre_file="");

	void skip_file();

	~FerretCOT();

	void setup(block Deltain, std::string pre_file = "", bool *choice=nullptr, block seed=zero_block);

	void setup(std::string pre_file = "", bool *choice = nullptr, block seed= zero_block);

	void send_cot(block * data, int64_t length) override;

	void recv_cot(block* data, const bool * b, int64_t length) override;

	void rcot(block *data, int64_t num);

	int64_t rcot_inplace(block *ot_buffer, int64_t length, block seed = zero_block);

	int64_t byte_memory_need_inplace(int64_t ot_need);

	void assemble_state(void * data, int64_t size);

	int disassemble_state(const void * data, int64_t size);

	int64_t state_size();
private:
	block ch[2];

	IOChannel **ios;
	int party, threads;
	int64_t M;
	bool is_malicious;
	bool extend_initialized;

	block * ot_pre_data = nullptr;
	block * ot_data = nullptr;

	std::string pre_ot_filename;

	BaseCot *base_cot = nullptr;
	OTPre *pre_ot = nullptr;
	ThreadPool *pool = nullptr;
	MpcotReg *mpcot = nullptr;
	LpnF2<10> *lpn_f2 = nullptr;

	void online_sender(block *data, int64_t length);

	void online_recver(block *data, const bool *b, int64_t length);

	void set_param();

	void set_preprocessing_param();

	void extend_initialization();

	void extend(block* ot_output, MpcotReg *mpfss, OTPre *preot,
			LpnF2<10> *lpn, block *ot_input, block seed = zero_block);

	void extend_f2k(block *ot_buffer);

	void extend_f2k();

	int64_t silent_ot_left();

	void write_pre_data128_to_file(void* loc, __uint128_t delta, std::string filename);

	__uint128_t read_pre_data128_from_file(void* pre_loc, std::string filename);
};

}  // namespace emp
#endif  // EMP_FERRET_COT_H_
