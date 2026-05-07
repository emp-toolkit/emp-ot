// Out-of-line definitions for FerretCOT. See ferret_cot.h for the API.

#include "emp-ot/ot_extension/ferret/ferret_cot.h"
#include "emp-ot/ot_extension/ferret/mpcot_reg.h"
#include "emp-ot/ot_extension/ferret/lpn_f2.h"
#include "emp-ot/ot_extension/softspoken/softspoken_ot.h"

namespace emp {

FerretCOT::FerretCOT(int party, int threads, IOChannel **ios,
		bool malicious, bool run_setup, PrimalLPNParameter param,
		std::unique_ptr<OT> base_ot) {
	this->party = party;
	this->threads = threads;
	io = ios[0];
	this->ios = ios;
	this->is_malicious = malicious;
	pool = std::make_unique<ThreadPool>(threads);
	this->param = param;
	this->base_ot_ = std::move(base_ot);

	this->extend_initialized = false;

	if(run_setup) {
		if(party == ALICE) {
			PRG prg;
			prg.random_block(&Delta);
			Delta = (Delta & lsb_clear_mask) ^ lsb_only_mask;
			setup(Delta);
		} else setup();
	}
}

FerretCOT::~FerretCOT() = default;

void FerretCOT::extend(block* ot_output, MpcotReg *mpcot,
		LpnF2<10> *lpn, block *ot_input, block seed) {
	if(party == ALICE) mpcot->sender_init(Delta);
	else mpcot->recver_init();
	// ot_input slicing: cGGM level corrections consume
	// ot_input[0 .. tree_n*(h-1)) (mpcot reads them directly via
	// pre_cot_data). The first 128 entries are also re-read by the
	// malicious consistency check (aliasing both reads is fine; both
	// are non-destructive). LPN base reads from ot_input + 128 onward.
	mpcot->mpcot(ot_output, ot_input);
	lpn->compute(ot_output, ot_input + MpcotReg::kConsistCheckCotNum, seed);
}

// Run one extend round. ot_buffer = nullptr writes to the internal
// ot_data buffer (rcot_send drains it via memcpy); a non-null buffer
// writes directly into the caller's storage. Either way the trailing
// M-block tail of the new output is copied back into ot_pre_data to
// seed the next round.
void FerretCOT::extend_f2k(block *ot_buffer) {
	if (ot_buffer == nullptr) ot_buffer = ot_data.data();
	extend(ot_buffer, mpcot.get(), lpn_f2.get(), ot_pre_data.data());
	memcpy(ot_pre_data.data(), ot_buffer + ot_limit, M * sizeof(block));
	ot_used = 0;
}

void FerretCOT::setup(block Deltain) {
	this->Delta = Deltain;
	setup();
}

void FerretCOT::setup() {
	lpn_f2 = std::make_unique<LpnF2<10>>(party, param.n, param.k, pool.get(), io, pool->size());
	mpcot  = std::make_unique<MpcotReg>(party, threads, param.n, param.t, param.log_bin_sz, pool.get(), ios);
	if (is_malicious) mpcot->set_malicious();

	// M base COTs per extend round = LPN k + cGGM level corrections
	// (tree_n × (h-1)) + 128 for the malicious consistency check.
	M        = param.k + mpcot->tree_n * (mpcot->tree_height - 1)
	           + MpcotReg::kConsistCheckCotNum;
	ot_limit = param.n - M;
	ot_used  = ot_limit;
	extend_initialized = true;

	ot_pre_data.resize(M);

	// Bootstrap: SoftSpokenOT<8> produces the M base COTs that seed
	// the first extend. Δ and malicious mode flow through; if no
	// base_ot was supplied, SoftSpoken builds its own OTPVW.
	SoftSpokenOT<8> ssp(io, std::move(base_ot_));
	if (is_malicious) ssp.set_malicious(true);
	if (party == ALICE) { ssp.setup_send(Delta); ssp.rcot_send(ot_pre_data.data(), M); }
	else                { ssp.setup_recv();      ssp.rcot_recv(ot_pre_data.data(), M); }
}

void FerretCOT::rcot_send(block *data, int64_t num) {
	if (!extend_initialized)
		error("Run setup before extending");
	if (ot_data.empty()) {
		ot_data.resize(param.n);
		// Zero-fill on first allocation: matches the historical
		// value-init behaviour. Some code paths read ot_data slots
		// before any extend() has populated them (e.g. silent_ot_left
		// underflow protection).
		std::fill(ot_data.begin(), ot_data.end(), zero_block);
	}

	int64_t produced = 0;

	// 1) Drain whatever's already buffered from a previous call.
	int64_t left = ot_limit - ot_used;
	if (left > 0) {
		int64_t take = std::min<int64_t>(num, left);
		memcpy(data, ot_data.data() + ot_used, take * sizeof(block));
		ot_used  += take;
		produced += take;
	}

	// 2) While the caller's remaining buffer can hold a full extend
	//    output (param.n = ot_limit useful + M tail), produce in place.
	while (num - produced >= param.n) {
		extend_f2k(data + produced);
		produced += ot_limit;
		ot_used   = ot_limit;  // internal buffer is "drained"
	}

	// 3) Final tail: extend into the internal buffer, copy out.
	while (produced < num) {
		extend_f2k();
		int64_t take = std::min<int64_t>(num - produced, ot_limit);
		memcpy(data + produced, ot_data.data(), take * sizeof(block));
		ot_used   = take;
		produced += take;
	}
}

int64_t FerretCOT::byte_memory_need_inplace(int64_t ot_need) {
	int64_t round = (ot_need - 1) / ot_limit;
	return round * ot_limit + param.n;
}

// In-place extend: write directly into the caller's buffer with no
// intermediate copy through ot_data. `byte_space` must equal
// byte_memory_need_inplace(ot_need); returns the number of usable COTs.
int64_t FerretCOT::rcot_inplace(block *ot_buffer, int64_t byte_space, block seed) {
	if(byte_space < param.n) error("space not enough");
	if((byte_space - M) % ot_limit != 0) error("call byte_memory_need_inplace \
			to get the correct length of memory space");
	int64_t ot_output_n = byte_space - M;
	int64_t round = ot_output_n / ot_limit;
	block *pt = ot_buffer;
	for(int64_t i = 0; i < round; ++i) {
		if(this->is_malicious) seed = zero_block;
		extend(pt, mpcot.get(), lpn_f2.get(), ot_pre_data.data(), seed);
		pt += ot_limit;
		memcpy(ot_pre_data.data(), pt, M*sizeof(block));
	}
	return ot_output_n;
}

}  // namespace emp
