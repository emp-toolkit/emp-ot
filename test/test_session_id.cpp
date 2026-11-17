// Session ids of OT objects (ot.h, svole.h). An object whose sid was not set
// before its first use takes its channel's next session id at that first use,
// so the two parties agree on it and a channel's top-level objects get distinct
// ids, whatever order they were built in. A sid set before the first use is
// kept, an sVOLE seeds its public LPN matrix from the id it took, and on a
// channel without a session root the id stays zero. Two-party via the `run`
// script, on EMP_PORT and EMP_PORT + 1.
#include "test/test.h"
#include <vector>
using namespace std;

static bool is_zero(const block &b) {
	const block zero = makeBlock(0, 0);
	return cmpBlock(&b, &zero, 1);
}

// Each party sends its id to the other; both must hold the same one.
static block agreed(NetIO *io, int party, const SessionID &id, const char *what) {
	block mine = id.value(), theirs;
	if (party == ALICE) {
		io->send_block(&mine, 1);
		io->recv_block(&theirs, 1);
	} else {
		io->recv_block(&theirs, 1);
		io->send_block(&mine, 1);
		io->flush();
	}
	expecting(cmpBlock(&mine, &theirs, 1), what);
	expecting(!is_zero(mine), "test_session_id: an object on a channel with a "
	                          "session root kept the zero id");
	return mine;
}

int main(int argc, char **argv) {
	const int party = parse_party(argv);
	const int port = peer_port();
	constexpr int64_t length = int64_t{1} << 12;

	{
		auto io = party == ALICE ? NetIO::listen(port, true)
		                         : NetIO::connect(peer_ip(), port, true);
		// Built in one order, first used in the other.
		IKNP built_first(party, io.get());
		IKNP built_second(party, io.get());
		check_cot(&built_second, io.get(), party, length);
		check_cot(&built_first, io.get(), party, length);
		CO co(io.get());
		check_ot(&co, io.get(), party, 128);
		Ferret ferret(party, io.get(), /*malicious=*/true, nullptr, tuning::ferret_b9);
		check_rcot(&ferret, io.get(), party, length);
		SoftSpoken<8> softspoken(party, io.get());
		check_cot(&softspoken, io.get(), party, length);
		PVW pvw(io.get());
		check_ot(&pvw, io.get(), party, 128);
		F2kVOLE<AuthValueF2k> vole(party, io.get(), /*malicious=*/true, tuning::ferret_b9);
		std::vector<AuthValueF2k> vole_out(vole.chunk_aligned_buf_sz());
		vole.run(vole_out.data(), (int64_t)vole_out.size());
		IKNP pinned(party, io.get());
		const block pin = makeBlock(0x7069, 0x6e6e6564);
		pinned.set_sid(pin);
		check_cot(&pinned, io.get(), party, length);

		const block ids[] = {
		    agreed(io.get(), party, built_second.session_id(), "test_session_id: IKNP ids differ"),
		    agreed(io.get(), party, built_first.session_id(), "test_session_id: IKNP ids differ"),
		    agreed(io.get(), party, co.session_id(), "test_session_id: CO ids differ"),
		    agreed(io.get(), party, ferret.session_id(), "test_session_id: Ferret ids differ"),
		    agreed(io.get(), party, softspoken.session_id(),
		           "test_session_id: SoftSpoken<8> ids differ"),
		    agreed(io.get(), party, pvw.session_id(), "test_session_id: PVW ids differ"),
		    agreed(io.get(), party, vole.session_id(), "test_session_id: F2kVOLE ids differ"),
		};
		for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); ++i)
			for (size_t j = i + 1; j < sizeof(ids) / sizeof(ids[0]); ++j)
				expecting(!cmpBlock(&ids[i], &ids[j], 1),
				          "test_session_id: two top-level objects drew the same id");
		const block lpn_seed = vole.lpn_->prg_key();
		const block want = svole_lpn_seed(AuthValueF2k::kLpnSeedDomain, vole.session_id().value());
		expecting(cmpBlock(&lpn_seed, &want, 1),
		          "test_session_id: the sVOLE LPN matrix is not seeded from its id");
		const block kept = pinned.session_id().value();
		expecting(cmpBlock(&kept, &pin, 1),
		          "test_session_id: a sid set before the first use was replaced");
	}
	{
		auto io = party == ALICE
		    ? NetIO::listen(port + 1, true, NetIO::SessionRoot::none)
		    : NetIO::connect(peer_ip(), port + 1, true, NetIO::SessionRoot::none);
		IKNP ot(party, io.get());
		check_cot(&ot, io.get(), party, length);
		expecting(is_zero(ot.session_id().value()),
		          "test_session_id: an object on a channel without a session root "
		          "drew an id");
	}
	if (party == ALICE) cout << "session ids: OK" << endl;
	return 0;
}
