template<typename T>
FerretCOT<T>::FerretCOT(int party, int threads, T **ios,
		bool malicious, bool run_setup) {
	this->party = party;
	this->threads = threads;
	io = ios[0];
	this->ios = ios;
	this->is_malicious = malicious;
	one = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);
	ch[0] = zero_block;
	base_cot = new BaseCot<T>(party, io, malicious);
	pool = new ThreadPool(threads);
	this->extend_initialized = false;

	if(run_setup) {
		if(party == ALICE) {
			PRG prg;
			prg.random_block(&Delta);
			Delta = Delta & one;
			Delta = Delta ^ 0x1;
			setup(Delta);
		} else setup();
	}
}

template<typename T>
FerretCOT<T>::~FerretCOT() {
	if (ot_pre_data != nullptr) {
		delete[] ot_pre_data;
	}
	if (ot_data != nullptr) delete[] ot_data;
	if(pre_ot != nullptr) delete pre_ot;
	delete base_cot;
	delete pool;
	if(lpn_f2 != nullptr) delete lpn_f2;
	if(mpcot != nullptr) delete mpcot;
}

template<typename T>
void FerretCOT<T>::extend_initialization() {
	lpn_f2 = new LpnF2<T, 10>(party, N_REG, K_REG, pool, io, pool->size());
	mpcot = new MpcotReg<T>(party, threads, N_REG, T_REG, BIN_SZ_REG, pool, ios);
	if(is_malicious) mpcot->set_malicious();

	pre_ot = new OTPre<T>(io, mpcot->tree_height-1, mpcot->tree_n);
	M = K_REG + pre_ot->n + mpcot->consist_check_cot_num;
	ot_limit = N_REG - M;
	ot_used = ot_limit;
	extend_initialized = true;
}

// extend f2k in detail
template<typename T>
void FerretCOT<T>::extend(block* ot_output, MpcotReg<T> *mpcot, OTPre<T> *preot, 
		LpnF2<T, 10> *lpn, block *ot_input) {
	if(party == ALICE) mpcot->sender_init(Delta);
	else mpcot->recver_init();
	mpcot->mpcot(ot_output, preot, ot_input);
	lpn->compute(ot_output, ot_input+mpcot->consist_check_cot_num);
}

// extend f2k (customized location)
template<typename T>
void FerretCOT<T>::extend_f2k(block *ot_buffer) {
	if(party == ALICE)
	    pre_ot->send_pre(ot_pre_data, Delta);
	else pre_ot->recv_pre(ot_pre_data);
	extend(ot_buffer, mpcot, pre_ot, lpn_f2, ot_pre_data);
	memcpy(ot_pre_data, ot_buffer+ot_limit, M*sizeof(block));
	ot_used = 0;
}

// extend f2k
template<typename T>
void FerretCOT<T>::extend_f2k() {
	extend_f2k(ot_data);
}

template<typename T>
void FerretCOT<T>::extend_once_dual_lpn(block *ot_pre_data_buf,
		int64_t n, int64_t np, int64_t t, int64_t logbin) {
	block *ot_pre_data_buf_input = new block[np];
	memset(ot_pre_data_buf, 0, n*16);

	block shared_seed;
	if(party == ALICE) {
		PRG prg;
		prg.random_block(&shared_seed, 1);
		ios[0]->send_data(&shared_seed, sizeof(block));
		ios[0]->flush();
	} else {
		ios[0]->recv_data(&shared_seed, sizeof(block));
	}

	MpcotReg<T> mpcot_pre(party, threads, np, t,
			logbin, pool, ios);
	block *ot_data_check_buf = nullptr;
	if(is_malicious) {
		mpcot_pre.set_malicious();
		ot_data_check_buf = new block[mpcot_pre.consist_check_cot_num];
		base_cot->cot_gen(ot_data_check_buf, mpcot_pre.consist_check_cot_num);
	}
	OTPre<T> pre_ot(ios[0], logbin, t);
	DualLpnF2<T> duallpn(party, n, np, pool, io, pool->size());

// TODO basecot optimization: combine these two process?
	base_cot->cot_gen(&pre_ot, pre_ot.n);

	if(party == ALICE) mpcot_pre.sender_init(Delta);
	else mpcot_pre.recver_init();
	mpcot_pre.mpcot(ot_pre_data_buf_input, &pre_ot, ot_data_check_buf);
	duallpn.compute_opt(ot_pre_data_buf, ot_pre_data_buf_input, shared_seed);

	delete[] ot_pre_data_buf_input;
	if(is_malicious) {
		delete[] ot_data_check_buf;
	}
}

template<typename T>
void FerretCOT<T>::extend_once_primal_lpn(block *ot_pre_data_buf,
		block *ot_pre_data_inbuf,
		int64_t n, int64_t k, int64_t t, int64_t logbin) {
	MpcotReg<T> mpcot_pre(party, threads, n, t, logbin, pool, ios);
	if(is_malicious) mpcot_pre.set_malicious();
	OTPre<T> pre_ot(ios[0], logbin, t);
	LpnF2<T, 10> lpn(party, n, k, pool, io, pool->size());

// TODO pre_ot choice bits input?
	if(party == ALICE) {
		pre_ot.send_pre(ot_pre_data_inbuf, Delta);
	} else {
		bool *choice_bits = new bool[pre_ot.n];
		for(int i = 0; i < pre_ot.n; ++i) {
			choice_bits[i] = getLSB(ot_pre_data_inbuf[i]);
		}
		pre_ot.recv_pre(ot_pre_data_inbuf, choice_bits);
		delete[] choice_bits;
	}

	extend(ot_pre_data_buf, &mpcot_pre, &pre_ot, &lpn,
		ot_pre_data_inbuf+pre_ot.n);
}

template<typename T>
void FerretCOT<T>::setup(block Deltain) {
	this->Delta = Deltain;
	setup();
	ch[1] = Delta;
}

template<typename T>
void FerretCOT<T>::setup() {
	ThreadPool pool2(1);
	auto fut = pool2.enqueue([this](){
		extend_initialization();
	});

	if(party == BOB) base_cot->cot_gen_pre();
	else base_cot->cot_gen_pre(Delta);

	// round 1: expand by dual-lpn
	block *ot_pre_data_rd1 = new block[N_REG_DUAL_RD0];
	memset(ot_pre_data_rd1, 0, N_REG_DUAL_RD0*sizeof(block));
	extend_once_dual_lpn(ot_pre_data_rd1, N_REG_DUAL_RD0, NP_REG_DUAL_RD0,
			T_REG_DUAL_RD0, BIN_SZ_REG_DUAL_RD0);

	// round 2: expand by primal-lpn
	block *ot_pre_data_rd2 = new block[N_REG_PRIMAL_RD1];
	memset(ot_pre_data_rd2, 0, N_REG_PRIMAL_RD1*sizeof(block));
	extend_once_primal_lpn(ot_pre_data_rd2, ot_pre_data_rd1, N_REG_PRIMAL_RD1,
			K_REG_PRIMAL_RD1, T_REG_PRIMAL_RD1, BIN_SZ_REG_PRIMAL_RD1);
	delete[] ot_pre_data_rd1;

	// round 3: expand by primal-lpn
	if(ot_pre_data == nullptr)
		this->ot_pre_data = new block[N_REG_PRIMAL_RD2];
	memset(this->ot_pre_data, 0, N_REG_PRIMAL_RD2*sizeof(block));
	extend_once_primal_lpn(ot_pre_data, ot_pre_data_rd2, N_REG_PRIMAL_RD2,
			K_REG_PRIMAL_RD2, T_REG_PRIMAL_RD2, BIN_SZ_REG_PRIMAL_RD2);
	delete[] ot_pre_data_rd2;

	fut.get();
}

template<typename T>
void FerretCOT<T>::rcot(block *data, int64_t num) {
	if(ot_data == nullptr) {
		ot_data = new block[N_REG];
		memset(ot_data, 0, N_REG*sizeof(block));
	}
	if(extend_initialized == false) 
		error("Run setup before extending");
	if(num <= silent_ot_left()) {
		memcpy(data, ot_data+ot_used, num*sizeof(block));
		ot_used += num;
		return;
	}
	block *pt = data;
	int64_t gened = silent_ot_left();
	if(gened > 0) {
		memcpy(pt, ot_data+ot_used, gened*sizeof(block));
		pt += gened;
	}
	int64_t round_inplace = (num-gened-M) / ot_limit;
	int64_t last_round_ot = num-gened-round_inplace*ot_limit;
	bool round_memcpy = last_round_ot>ot_limit?true:false;
	if(round_memcpy) last_round_ot -= ot_limit;
	for(int64_t i = 0; i < round_inplace; ++i) {
		extend_f2k(pt);
		ot_used = ot_limit;
		pt += ot_limit;
	}
	if(round_memcpy) {
		extend_f2k();
		memcpy(pt, ot_data, ot_limit*sizeof(block));
		pt += ot_limit;
	}
	if(last_round_ot > 0) {
		extend_f2k();
		memcpy(pt, ot_data, last_round_ot*sizeof(block));
		ot_used = last_round_ot;
	}
}

template<typename T>
int64_t FerretCOT<T>::silent_ot_left() {
	return ot_limit-ot_used;
}

template<typename T>
int64_t FerretCOT<T>::byte_memory_need_inplace(int64_t ot_need) {
	int64_t round = (ot_need - 1) / ot_limit;
	return round * ot_limit + N_REG;
}

// extend f2k (benchmark)
// parameter "length" should be the return of "byte_memory_need_inplace"
// output the number of COTs that can be used
template<typename T>
int64_t FerretCOT<T>::rcot_inplace(block *ot_buffer, int64_t byte_space) {
	if(byte_space < N_REG) error("space not enough");
	if((byte_space - M) % ot_limit != 0) error("call byte_memory_need_inplace \
			to get the correct length of memory space");
	int64_t ot_output_n = byte_space - M;
	int64_t round = ot_output_n / ot_limit;
	block *pt = ot_buffer;
	for(int64_t i = 0; i < round; ++i) {
		if(party == ALICE)
		    pre_ot->send_pre(ot_pre_data, Delta);
		else pre_ot->recv_pre(ot_pre_data);
		extend(pt, mpcot, pre_ot, lpn_f2, ot_pre_data);
		pt += ot_limit;
		memcpy(ot_pre_data, pt, M*sizeof(block));
	}
	return ot_output_n;
}

template<typename T>
void FerretCOT<T>::online_sender(block *data, int64_t length) {
	bool *bo = new bool[length];
	io->recv_bool(bo, length*sizeof(bool));
	for(int64_t i = 0; i < length; ++i) {
		data[i] = data[i] ^ ch[bo[i]];
	}
	delete[] bo;
}

template<typename T>
void FerretCOT<T>::online_recver(block *data, const bool *b, int64_t length) {
	bool *bo = new bool[length];
	for(int64_t i = 0; i < length; ++i) {
		bo[i] = b[i] ^ getLSB(data[i]);
	}
	io->send_bool(bo, length*sizeof(bool));
	delete[] bo;
}

template<typename T>
void FerretCOT<T>::send_cot(block * data, int64_t length) {
	rcot(data, length);
	online_sender(data, length);
}

template<typename T>
void FerretCOT<T>::recv_cot(block* data, const bool * b, int64_t length) {
	rcot(data, length);
	online_recver(data, b, length);
}

template<typename T>
void FerretCOT<T>::assemble_state(void * data, int64_t size) {
	unsigned char * array = (unsigned char * )data;
	memcpy(array, &party, sizeof(int64_t));
	memcpy(array + sizeof(int64_t), &N_REG, sizeof(int64_t));
	memcpy(array + sizeof(int64_t) * 2, &T_REG, sizeof(int64_t));
	memcpy(array + sizeof(int64_t) * 3, &K_REG, sizeof(int64_t));
	memcpy(array + sizeof(int64_t) * 4, &Delta, sizeof(block));	
	memcpy(array + sizeof(int64_t) * 4 + sizeof(block), ot_pre_data, sizeof(block)*N_REG_PRIMAL_RD2);
	if (ot_pre_data!= nullptr)
		delete[] ot_pre_data;
	ot_pre_data = nullptr;
}

template<typename T>
int FerretCOT<T>::disassemble_state(const void * data, int64_t size) {
	const unsigned char * array = (const unsigned char * )data;
	int64_t n2 = 0, t2 = 0, k2 = 0, party2 = 0;
	ot_pre_data = new block[N_REG_PRIMAL_RD2];
	memcpy(&party2, array, sizeof(int64_t));
	memcpy(&n2, array + sizeof(int64_t), sizeof(int64_t));
	memcpy(&t2, array + sizeof(int64_t) * 2, sizeof(int64_t));
	memcpy(&k2, array + sizeof(int64_t) * 3, sizeof(int64_t));
	if(party2 != party or n2 != N_REG or t2 != T_REG or k2 != K_REG) {
		return -1;
	}
	memcpy(&Delta, array + sizeof(int64_t) * 4, sizeof(block));	
	memcpy(ot_pre_data, array + sizeof(int64_t) * 4 + sizeof(block), sizeof(block)*N_REG_PRIMAL_RD2);

	extend_initialization();
	ch[1] = Delta;
	return 0;
}

template<typename T>
int64_t FerretCOT<T>::state_size() {
	return sizeof(int64_t) * 4 + sizeof(block) + sizeof(block)*N_REG_PRIMAL_RD2;
}