#ifndef EMP_FERRET_COT_H_
#define EMP_FERRET_COT_H_
#include "emp-ot/ot.h"
#include "emp-ot/ot_extension/ferret/constants.h"
#include "emp-ot/ot.h"
#include <memory>

// Forward-declare ferret internals so the public header doesn't pull
// in the SPCOT / cGGM transitive closure.
// The .cpp #includes the real headers; std::unique_ptr<T> works with
// forward-declared T as long as the dtor is out-of-line (it is).

namespace emp {
class MpcotReg;
template <int d> class LpnF2;
}  // namespace emp

namespace emp {

/*
 * Ferret COT binary version
 * [REF] Implementation of "Ferret: Fast Extension for coRRElated oT with small communication"
 * https://eprint.iacr.org/2020/924.pdf
 *
 */
class FerretCOT: public RandomCOT {
public:
	PrimalLPNParameter param;
	int64_t ot_used, ot_limit;

	// `base_ot` is forwarded to the internal SoftSpokenOT<8> bootstrap.
	// Default (nullptr) → SoftSpoken constructs its own OTPVW base. The
	// supplied OT* is consumed on the first cold-start bootstrap (when
	// no pre-OT file is present); subsequent bootstraps fall back to
	// the default if any.
	FerretCOT(int party, int threads, IOChannel **ios, bool malicious = false, bool run_setup = true,
			PrimalLPNParameter param = ferret_b13, std::string pre_file="",
			std::unique_ptr<OT> base_ot = nullptr);

	void skip_file();

	~FerretCOT();

	void setup(block Deltain, std::string pre_file = "", bool *choice=nullptr, block seed=zero_block);

	void setup(std::string pre_file = "", bool *choice = nullptr, block seed= zero_block);

	// RandomCOT contract: produce `num` LSB-encoded RCOT outputs. The
	// role is fixed at construction, so the work is identical for
	// sender and receiver — rcot_send holds the body, rcot_recv just
	// delegates. RandomCOT::send_cot / recv_cot build the
	// chosen-choice COT layer on top via the standard 1-bit-per-COT
	// correction.
	void rcot_send(block* data, int64_t num) override;
	void rcot_recv(block* data, int64_t num) override { rcot_send(data, num); }

	int64_t rcot_inplace(block *ot_buffer, int64_t length, block seed = zero_block);

	int64_t byte_memory_need_inplace(int64_t ot_need);

	void assemble_state(void * data, int64_t size);

	int disassemble_state(const void * data, int64_t size);

	int64_t state_size();
private:
	IOChannel **ios;
	int party, threads;
	int64_t M;
	bool is_malicious;
	bool extend_initialized;

	BlockVec ot_pre_data;  // sized to M when active; .empty() means "none"
	BlockVec ot_data;      // sized to param.n; lazily resized on first use

	std::string pre_ot_filename;

	std::unique_ptr<ThreadPool> pool;
	std::unique_ptr<MpcotReg>  mpcot;
	std::unique_ptr<LpnF2<10>> lpn_f2;
	std::unique_ptr<OT> base_ot_;  // forwarded into SoftSpoken on first cold-start bootstrap

	void extend_initialization();

	void extend(block* ot_output, MpcotReg *mpfss,
			LpnF2<10> *lpn, block *ot_input, block seed = zero_block);

	// One-arg form. Pass nullptr to write to the internal buffer
	// (caller will copy out); pass a user buffer to write directly.
	void extend_f2k(block *ot_buffer = nullptr);

	int64_t silent_ot_left();

	void write_pre_data128_to_file(void* loc, __uint128_t delta, std::string filename);

	__uint128_t read_pre_data128_from_file(void* pre_loc, std::string filename);
};

}  // namespace emp
#endif  // EMP_FERRET_COT_H_
