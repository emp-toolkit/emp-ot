#include "emp-ot/ferret/ferret_cot.h"
#include "emp-ot/ferret/dual_lpn_f2.h"

int party, port;
const static int threads = 4;

int main(int argc, char **argv) {
    parse_party_and_port(argv, &party, &port);
	NetIO* ios[threads];
	for(int i = 0; i < threads; ++i)
		ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port+i);

    // input rcot
    int64_t n = 9216;
    int64_t np = 65536;
    block *nn = new block[n];
    block *kk = new block[np];
    FerretCOT<NetIO> *ferretcot = new FerretCOT<NetIO>(party,
        threads, ios, false);
    ferretcot->rcot(kk, np);

    // shared seed
    block seed;
    if(party == ALICE) {
        PRG prg;
        prg.random_block(&seed, 1);
        ios[0]->send_data(&seed, sizeof(block));
        ios[0]->flush();
    } else {
        ios[0]->recv_data(&seed, sizeof(block));
    }

    // dual lpn
    ThreadPool *pool = new ThreadPool(threads);
    DualLpnF2<NetIO> *duallpn = new DualLpnF2<NetIO>(party, n, np,
            pool, ios[0], threads);
    auto start = clock_start();
    duallpn->compute(nn, kk, seed);
    std::cout << time_from(start) << " us" << std::endl;

    // check correctness
    block delta;
    if(party == ALICE) {
        delta = ferretcot->Delta;
        ios[0]->send_data(&delta, sizeof(block));
        ios[0]->send_data(nn, n*sizeof(block));
        ios[0]->flush();
    } else {
        block *nn2 = new block[n];
        ios[0]->recv_data(&delta, sizeof(block));
        ios[0]->recv_data(nn2, n*sizeof(block));
        block choose[2];
        choose[0] = zero_block;
        choose[1] = delta;
        for(int i = 0; i < n; ++i) {
            nn[i] = nn[i] ^ choose[getLSB(nn[i])];
        }
        if(!cmpBlock(nn, nn2, n)) {
            error("lpn error");
        }
        delete[] nn2;
    }

    delete pool;
    delete ferretcot;
    delete[] nn;
    delete[] kk;
    delete duallpn;
    for(int i = 0; i < threads; ++i)
        delete ios[i];

    return 0;
}