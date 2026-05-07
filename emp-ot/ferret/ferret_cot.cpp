// Out-of-line definitions for FerretCOT. See ferret_cot.h for the API.

#include "emp-ot/ferret/ferret_cot.h"
#include "emp-ot/ferret/mpcot_reg.h"
#include "emp-ot/ferret/lpn_f2.h"
#include "emp-ot/softspoken/softspoken_ot.h"

namespace emp {

FerretCOT::FerretCOT(int party, int threads, IOChannel **ios,
		bool malicious, bool run_setup, PrimalLPNParameter param, std::string pre_file,
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
			setup(Delta, pre_file);
		} else setup(pre_file);
	}
}

void FerretCOT::skip_file() {
	delete[] ot_pre_data;
	ot_pre_data = nullptr;
}

FerretCOT::~FerretCOT() {
	// Persist pre-OT data to disk for the next session, if any.
	if (ot_pre_data != nullptr) {
		__uint128_t delta128 = (party == ALICE) ? (__uint128_t)Delta : 0;
		write_pre_data128_to_file((void*)ot_pre_data, delta128, pre_ot_filename);
		delete[] ot_pre_data;
	}
	delete[] ot_data;
	// unique_ptr members destroy in reverse-declared order automatically.
}

void FerretCOT::extend_initialization() {
	if (extend_initialized) return;
	lpn_f2 = std::make_unique<LpnF2<10>>(party, param.n, param.k, pool.get(), io, pool->size());
	mpcot  = std::make_unique<MpcotReg>(party, threads, param.n, param.t, param.log_bin_sz, pool.get(), ios);
	if (is_malicious) mpcot->set_malicious();

	// cGGM (Half-Tree) consumes one base COT per tree level: tree_n
	// trees × (tree_height - 1) levels per tree. Plus param.k base
	// COTs for LPN and 128 for the malicious consistency check.
	M        = param.k + mpcot->tree_n * (mpcot->tree_height - 1)
	           + mpcot->consist_check_cot_num;
	ot_limit = param.n - M;
	ot_used  = ot_limit;
	extend_initialized = true;
}

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
	lpn->compute(ot_output, ot_input + mpcot->consist_check_cot_num, seed);
}

// Run one extend round. ot_buffer = nullptr writes to the internal
// ot_data buffer (rcot_send drains it via memcpy); a non-null buffer
// writes directly into the caller's storage. Either way the trailing
// M-block tail of the new output is copied back into ot_pre_data to
// seed the next round.
void FerretCOT::extend_f2k(block *ot_buffer) {
	if (ot_buffer == nullptr) ot_buffer = ot_data;
	extend(ot_buffer, mpcot.get(), lpn_f2.get(), ot_pre_data);
	memcpy(ot_pre_data, ot_buffer + ot_limit, M * sizeof(block));
	ot_used = 0;
}

void FerretCOT::setup(block Deltain, std::string pre_file, bool *choice, block seed) {
	this->Delta = Deltain;
	if(this->is_malicious) seed = zero_block;
	setup(pre_file, choice, seed);
}

void FerretCOT::setup(std::string pre_file, bool *choice, block seed) {
	if(pre_file != "") pre_ot_filename = pre_file;
	else {
		pre_ot_filename=(party==ALICE?PRE_OT_DATA_REG_SEND_FILE:PRE_OT_DATA_REG_RECV_FILE);
	}

	// extend_initialization() must complete before bootstrap so M and the
	// mpcot dimensions are known: SoftSpokenOT produces exactly M COTs,
	// and ot_pre_data is sized to M.
	extend_initialization();

	ot_pre_data = new block[M];
	bool hasfile = file_exists(pre_ot_filename), hasfile2;
	if(party == ALICE) {
		io->send_data(&hasfile, sizeof(bool));
		io->flush();
		io->recv_data(&hasfile2, sizeof(bool));
	} else {
		io->recv_data(&hasfile2, sizeof(bool));
		io->send_data(&hasfile, sizeof(bool));
		io->flush();
	}
	if(hasfile && hasfile2) {
		Delta = (block)read_pre_data128_from_file((void*)ot_pre_data, pre_ot_filename);
	} else {
		// Bootstrap: SoftSpokenOT<8> directly produces the M base COTs
		// needed to seed the first steady-state extend. Δ is shared (the
		// same one used in subsequent cGGM corrections and the
		// consistency check). Malicious mode propagates: SoftSpoken's
		// PPRF + subspace VOLE checks compose with the downstream
		// MpcotReg consistency check to give end-to-end malicious
		// security.
		(void)choice; (void)seed;
		// Forward the user-supplied base OT into SoftSpoken's bootstrap;
		// SoftSpoken owns it from here. If we didn't get one, SoftSpoken
		// constructs its own OTPVW.
		SoftSpokenOT<8> ssp(io, std::move(base_ot_));
		if (this->is_malicious) ssp.set_malicious(true);
		if (party == ALICE) ssp.setup_send(Delta);
		else                ssp.setup_recv();
		if (party == ALICE) ssp.rcot_send(ot_pre_data, M);
		else                ssp.rcot_recv(ot_pre_data, M);
	}
}

void FerretCOT::rcot_send(block *data, int64_t num) {
	if (!extend_initialized)
		error("Run setup before extending");
	if (ot_data == nullptr) {
		ot_data = new block[param.n]();  // value-init zero-fills
	}

	int64_t produced = 0;

	// 1) Drain whatever's already buffered from a previous call.
	if (silent_ot_left() > 0) {
		int64_t take = std::min<int64_t>(num, silent_ot_left());
		memcpy(data, ot_data + ot_used, take * sizeof(block));
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
		memcpy(data + produced, ot_data, take * sizeof(block));
		ot_used   = take;
		produced += take;
	}
}

int64_t FerretCOT::silent_ot_left() {
	return ot_limit-ot_used;
}

void FerretCOT::write_pre_data128_to_file(void* loc, __uint128_t delta, std::string filename) {
	std::ofstream outfile(filename, std::ios::binary | std::ios::trunc);
	if (!outfile.is_open())
		error("create a directory to store pre-OT data");
	int64_t party64 = party;
	outfile.write(reinterpret_cast<const char*>(&party64), sizeof(int64_t));
	if (party == ALICE)
		outfile.write(reinterpret_cast<const char*>(&delta), 16);
	outfile.write(reinterpret_cast<const char*>(&param.n), sizeof(int64_t));
	outfile.write(reinterpret_cast<const char*>(&param.t), sizeof(int64_t));
	outfile.write(reinterpret_cast<const char*>(&param.k), sizeof(int64_t));
	outfile.write(reinterpret_cast<const char*>(loc), M * 16);
}

__uint128_t FerretCOT::read_pre_data128_from_file(void* pre_loc, std::string filename) {
	std::ifstream infile(filename, std::ios::binary);
	if (!infile.is_open())
		error("could not open pre-OT data file");
	int64_t in_party;
	infile.read(reinterpret_cast<char*>(&in_party), sizeof(int64_t));
	if (in_party != party) error("wrong party");

	__uint128_t delta = 0;
	if (party == ALICE)
		infile.read(reinterpret_cast<char*>(&delta), 16);
	int64_t nin, tin, kin;
	infile.read(reinterpret_cast<char*>(&nin), sizeof(int64_t));
	infile.read(reinterpret_cast<char*>(&tin), sizeof(int64_t));
	infile.read(reinterpret_cast<char*>(&kin), sizeof(int64_t));
	if (nin != param.n || tin != param.t || kin != param.k)
		error("wrong parameters");
	infile.read(reinterpret_cast<char*>(pre_loc), M * 16);
	infile.close();
	std::remove(filename.c_str());
	return delta;
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
		extend(pt, mpcot.get(), lpn_f2.get(), ot_pre_data, seed);
		pt += ot_limit;
		memcpy(ot_pre_data, pt, M*sizeof(block));
	}
	return ot_output_n;
}

void FerretCOT::assemble_state(void * data, int64_t size) {
	(void)size;
	auto* cur = static_cast<unsigned char*>(data);
	auto put = [&](auto const& v) { memcpy(cur, &v, sizeof v); cur += sizeof v; };
	int64_t party64 = party;
	put(party64); put(param.n); put(param.t); put(param.k); put(Delta);
	memcpy(cur, ot_pre_data, sizeof(block) * M);
	delete[] ot_pre_data;  // delete[] nullptr is well-defined; safe regardless
	ot_pre_data = nullptr;
}

int FerretCOT::disassemble_state(const void * data, int64_t size) {
	(void)size;
	auto const* cur = static_cast<const unsigned char*>(data);
	auto get = [&](auto& v) { memcpy(&v, cur, sizeof v); cur += sizeof v; };
	int64_t party2 = 0, n2 = 0, t2 = 0, k2 = 0;
	get(party2); get(n2); get(t2); get(k2); get(Delta);
	if (party2 != party || n2 != param.n || t2 != param.t || k2 != param.k)
		return -1;
	// Init must run before sizing/allocating ot_pre_data — M is a
	// derived constant from the steady-state mpcot/lpn dimensions.
	extend_initialization();
	ot_pre_data = new block[M];
	memcpy(ot_pre_data, cur, sizeof(block) * M);
	return 0;
}

int64_t FerretCOT::state_size() {
	// M is set by extend_initialization(); ensure it has run so callers
	// can size the state buffer before assemble/disassemble.
	if (!extend_initialized) extend_initialization();
	return sizeof(int64_t) * 4 + sizeof(block) + sizeof(block) * M;
}

}  // namespace emp
