template<typename T, int threads>
FerretCOT<T, threads>::FerretCOT(int party, T * ios[threads+1], bool malicious) {
	this->party = party;
	io = ios[0];
	this->ios = ios;
	this->is_malicious = malicious;
	one = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);
	ch[0] = zero_block;
	base_cot = new BaseCot(party, io, malicious);
	pool = new ThreadPool(threads);
	set_param();
	set_preprocessing_param();
	this->extend_initialized = false;

	if(party == ALICE) {
		PRG prg;
		prg.random_block(&Delta);
		Delta = Delta & one;
		Delta = Delta ^ 0x1;
		setup(Delta);
		Delta = Delta_f2k;
		ch[1] = Delta;
	} else setup();
}

template<typename T, int threads>
FerretCOT<T, threads>::~FerretCOT() {
	if (ot_pre_data != nullptr) {
		if(party == ALICE) write_pre_data128_to_file((void*)ot_pre_data, (__uint128_t)Delta_f2k, pre_ot_filename);
		else write_pre_data128_to_file((void*)ot_pre_data, (__uint128_t)0, pre_ot_filename);
		delete[] ot_pre_data;
	}
	if (ot_data != nullptr) delete[] ot_data;
	if(pre_ot != nullptr) delete pre_ot;
	delete base_cot;
	delete pool;
	if(lpn_f2 != nullptr) delete lpn_f2;
	if(mpcot != nullptr) delete mpcot;
}

template<typename T, int threads>
void FerretCOT<T, threads>::set_param() {
	this->n = N_REG;
	this->k = K_REG;
	this->t = T_REG;
	this->log_bin_sz = BIN_SZ_REG;
}

template<typename T, int threads>
void FerretCOT<T, threads>::set_preprocessing_param() {
	this->n_pre = N_PRE_REG;
	this->k_pre = K_PRE_REG;
	this->t_pre = T_PRE_REG;
	this->log_bin_sz_pre = BIN_SZ_PRE_REG;
}

template<typename T, int threads>
void FerretCOT<T, threads>::extend_initialization() {
	lpn_f2 = new LpnF2<10>(party, n, k, pool, io, pool->size());
	mpcot = new MpcotReg<threads>(party, n, t, log_bin_sz, pool, ios);
	if(is_malicious) mpcot->set_malicious();

	pre_ot = new OTPre<NetIO>(io, mpcot->tree_height-1, mpcot->tree_n);
	M = k + pre_ot->n + mpcot->consist_check_cot_num;
	ot_limit = n - n_pre;
	ot_used = ot_limit;
	extend_initialized = true;
}

// extend f2k in detail
template<typename T, int threads>
void FerretCOT<T, threads>::extend(block* ot_output, MpcotReg<threads> *mpcot, OTPre<NetIO> *preot, 
		LpnF2<10> *lpn, block *ot_input) {
	if(party == ALICE) mpcot->sender_init(Delta_f2k);
	else mpcot->recver_init();
	mpcot->mpcot(ot_output, preot, ot_input);
	lpn->compute(ot_output, ot_input+mpcot->consist_check_cot_num);
}

// extend f2k (customized location)
template<typename T, int threads>
void FerretCOT<T, threads>::extend_f2k(block *ot_buffer) {
	if(party == ALICE)
	    pre_ot->send_pre(ot_pre_data, Delta_f2k);
	else pre_ot->recv_pre(ot_pre_data);
	extend(ot_buffer, mpcot, pre_ot, lpn_f2, ot_pre_data);
	memcpy(ot_pre_data, ot_buffer+ot_limit, n_pre*sizeof(block));
	ot_used = 0;
}

// extend f2k
template<typename T, int threads>
void FerretCOT<T, threads>::extend_f2k() {
	extend_f2k(ot_data);
}

template<typename T, int threads>
void FerretCOT<T, threads>::setup(block Deltain, std::string pre_file) {
	this->Delta_f2k = Deltain;
	setup(pre_file);
}

template<typename T, int threads>
void FerretCOT<T, threads>::setup(std::string pre_file) {
	if(pre_file != "") pre_ot_filename = pre_file;
	else {
		pre_ot_filename=(party==ALICE?PRE_OT_DATA_REG_SEND_FILE:PRE_OT_DATA_REG_RECV_FILE);
	}

	ThreadPool pool2(1);
	auto fut = pool2.enqueue([this](){
		extend_initialization();
	});

	ot_pre_data = new block[n_pre];
	if(file_exists(pre_ot_filename) == true) {
		Delta_f2k = (block)read_pre_data128_from_file((void*)ot_pre_data, pre_ot_filename);
	} else {
		if(party == BOB) base_cot->cot_gen_pre();
		else base_cot->cot_gen_pre(Delta_f2k);

		MpcotReg<threads> mpcot_ini(party, n_pre, t_pre, log_bin_sz_pre, pool, ios);
		if(is_malicious) mpcot_ini.set_malicious();
		OTPre<NetIO> pre_ot_ini(ios[0], mpcot_ini.tree_height-1, mpcot_ini.tree_n);
		LpnF2<10> lpn(party, n_pre, k_pre, pool, io, pool->size());

		block pre_data_ini[k_pre+mpcot_ini.consist_check_cot_num];
		memset(this->ot_pre_data, 0, n_pre*16);

		base_cot->cot_gen(&pre_ot_ini, pre_ot_ini.n);
		base_cot->cot_gen(pre_data_ini, k_pre+mpcot_ini.consist_check_cot_num);
		extend(ot_pre_data, &mpcot_ini, &pre_ot_ini, &lpn, pre_data_ini);
	}

	fut.get();
}

template<typename T, int threads>
void FerretCOT<T, threads>::rcot(block *data, int num) {
	if(ot_data == nullptr) {
		ot_data = new block[n];
		memset(ot_data, 0, n*sizeof(block));
	}
	if(extend_initialized == false) 
		error("Run setup before extending");
	if(num <= silent_ot_left()) {
		memcpy(data, ot_data+ot_used, num*sizeof(block));
		ot_used += num;
		return;
	}
	int gened = silent_ot_left();
	if(gened > 0)
		memcpy(data, ot_data+ot_used, gened*sizeof(block));
	int round = (num-gened) / ot_limit;
	int last_round_ot = num-gened-round*ot_limit;
	for(int i = 0; i < round; ++i) {
		extend_f2k();
		memcpy(data+gened+i*ot_limit, ot_data, ot_limit*sizeof(block));
		ot_used = ot_limit;
	}
	extend_f2k();
	memcpy(data+gened+round*ot_limit, ot_data, last_round_ot*sizeof(block));
	ot_used = last_round_ot;
}

template<typename T, int threads>
int FerretCOT<T, threads>::silent_ot_left() {
	return ot_limit-ot_used;
}

template<typename T, int threads>
void FerretCOT<T, threads>::write_pre_data128_to_file(void* loc, __uint128_t delta, std::string filename) {
	FileIO fio(filename.c_str(), false);
	fio.send_data(&party, sizeof(int));
	if(party == ALICE) fio.send_data(&delta, 16);
	fio.send_data(loc, n_pre*16);
}

template<typename T, int threads>
__uint128_t FerretCOT<T, threads>::read_pre_data128_from_file(void* pre_loc, std::string filename) {
	FileIO fio(filename.c_str(), true);
	int in_party;
	fio.recv_data(&in_party, sizeof(int));
	if(in_party != party) error("wrong party");
	__uint128_t delta = 0;
	if(party == ALICE) fio.recv_data(&delta, 16);
	fio.recv_data(pre_loc, n_pre*16);
	std::remove(filename.c_str());
	return delta;
}

// extend f2k (benchmark)
// length = t * ot_limit + n_pre
template<typename T, int threads>
void FerretCOT<T, threads>::rcot_inplace(block *ot_buffer, int length) {
	if(length < n) error("space not enough");
	if((length - n_pre) % ot_limit != 0) error("length = t * ot_limit + n_pre");
	int round = (length - n_pre) / ot_limit;
	block *pt = ot_buffer;
	for(int i = 0; i < round; ++i) {
		if(party == ALICE)
		    pre_ot->send_pre(ot_pre_data, Delta_f2k);
		else pre_ot->recv_pre(ot_pre_data);
		extend(pt, mpcot, pre_ot, lpn_f2, ot_pre_data);
		pt += ot_limit;
		memcpy(ot_pre_data, pt, n_pre*sizeof(block));
	}
	ot_used = 0;
}

template<typename T, int threads>
void FerretCOT<T, threads>::online_sender(block *data, int length) {
	bool *bo = new bool[length];
	io->recv_bool(bo, length*sizeof(bool));
	for(int i = 0; i < length; ++i) {
		data[i] = data[i] ^ ch[bo[i]];
	}
	delete[] bo;
}

template<typename T, int threads>
void FerretCOT<T, threads>::online_recver(block *data, const bool *b, int length) {
	bool *bo = new bool[length];
	for(int i = 0; i < length; ++i) {
		bo[i] = b[i] ^ getLSB(data[i]);
	}
	io->send_bool(bo, length*sizeof(bool));
	delete[] bo;
}

template<typename T, int threads>
void FerretCOT<T, threads>::send_cot(block * data, int length) {
	rcot(data, length);
	online_sender(data, length);
}

template<typename T, int threads>
void FerretCOT<T, threads>::recv_cot(block* data, const bool * b, int length) {
	rcot(data, length);
	online_recver(data, b, length);
}
