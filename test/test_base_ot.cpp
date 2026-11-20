// Base-OT correctness test. Sweeps the base-OT protocols CO / PVW / CSW /
// BMM and, for each, runs the protocol and asserts the receiver's
// outputs via check_ot (which calls expecting() on mismatch). Correctness-only;
// throughput lives in bench/bench_base_ot.cpp. Two-party via the `run` script
// (loopback 127.0.0.1).
#include "test/test.h"
#include <cstring>
#include <vector>
using namespace std;

// Forwards to a real channel and keeps every byte it receives, so a test can
// inspect what the peer sent.
class RecordingIO final : public IOChannel {
public:
	explicit RecordingIO(IOChannel *inner) : inner_(inner) {}
	vector<uint8_t> received;
	void send_data_internal(const void *data, int64_t nbyte) override {
		inner_->send_data(data, nbyte);
	}
	void recv_data_internal(void *data, int64_t nbyte) override {
		inner_->recv_data(data, nbyte);
		const uint8_t *p = static_cast<const uint8_t *>(data);
		received.insert(received.end(), p, p + nbyte);
	}
	void flush() override { inner_->flush(); }

private:
	IOChannel *inner_;
};

// CSW's extraction check sends chi_i = H3(p_{i,0}) ^ H3(p_{i,1}). If a
// chosen-message ciphertext were the message XOR its bare pad, a receiver
// could test guesses of the message it did not choose; with the pads hashed
// into message keys, H3(c_{i,0} ^ m_{i,0}) ^ H3(c_{i,1} ^ m_{i,1}) must not
// reproduce chi_i. The messages are public and low-entropy on purpose.
static void check_csw_message_keys(NetIO *io, int party) {
	constexpr int64_t n = CSW::kMinLength;
	const block sid = makeBlock(0x5157C0DE5157C0DEULL, 0x0123456789ABCDEFULL);
	vector<block> m0(n), m1(n);
	for (int64_t i = 0; i < n; ++i) {
		m0[i] = makeBlock(i, 0);
		m1[i] = makeBlock(i, 1);
	}
	if (party == ALICE) {
		CSW csw(io);
		csw.set_sid(sid);
		csw.send(m0.data(), m1.data(), n);
		cout << "CSW message keys\t";
		return;
	}
	RecordingIO rec(io);
	CSW csw(&rec);
	csw.set_sid(sid);
	bool b[n];
	PRG prg;
	prg.random_bool(b, n);
	vector<block> out(n);
	csw.recv(out.data(), b, n);
	for (int64_t i = 0; i < n; ++i)
		expecting(cmpBlock(&out[i], b[i] ? &m1[i] : &m0[i], 1),
		          "CSW message keys: wrong output");

	// Received, in order: z, c_0[n], c_1[n], chi[n], the proof. Parse from the
	// end, copying into aligned storage.
	const int64_t tail = (3 * n + 1) * (int64_t)sizeof(block);
	expecting((int64_t)rec.received.size() > tail,
	          "CSW message keys: short transcript");
	const uint8_t *at = rec.received.data() + rec.received.size() - tail;
	vector<block> c0(n), c1(n), chi(n);
	memcpy(c0.data(), at, n * sizeof(block));
	memcpy(c1.data(), at + n * sizeof(block), n * sizeof(block));
	memcpy(chi.data(), at + 2 * n * sizeof(block), n * sizeof(block));
	auto h3 = [&](block x) {
		return RO("emp-ot:sf-rot-check:h3", sid).absorb(x).squeeze_block();
	};
	for (int64_t i = 0; i < n; ++i) {
		block guess = h3(c0[i] ^ m0[i]) ^ h3(c1[i] ^ m1[i]);
		expecting(!cmpBlock(&guess, &chi[i], 1),
		          "CSW message keys: the check reveals a hash of a message pad");
	}
	cout << "CSW message keys\t";
}

// Per-protocol correctness check via the assert-only check_ot helper.
template <typename T>
void run_one(const char *name, T *ot, NetIO *io, int party, int64_t length) {
	cout << name << "\t";
	check_ot<T>(ot, io, party, length);
}

int main(int argc, char **argv) {
	int port, party;
	party = parse_party(argv);
	port = peer_port();
	auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

	// Base OTs are the security-parameter-fixed bootstrap (128 of them);
	// keep the test at that natural size — small and fast in CI regardless
	// of NDEBUG.
	constexpr int64_t length = 128;
	cout << (party == ALICE ? "Alice" : "Bob")
	     << " — verifying " << length << " base OTs:\n";

	{
		CO co(io.get());
		run_one("CO", &co, io.get(), party, length);
	}
	{
		PVW pvw(io.get());
		run_one("PVW", &pvw, io.get(), party, length);
	}
	{
		// CSW and BMM set their sid explicitly, covering set_sid(); CO and
		// PVW above take the channel's next session id at first use.
		block sid = makeBlock(0xCAFEBABE12345678ULL, 0xDEADBEEFFACEFEEDULL);
		CSW csw(io.get());
		csw.set_sid(sid);
		run_one("CSW", &csw, io.get(), party, length);
	}
	{
		block sid = makeBlock(0xCAFEBABE12345678ULL, 0x0BADC0DE0DEFACE0ULL);
		BMM bmm(io.get());
		bmm.set_sid(sid);
		run_one("BMM", &bmm, io.get(), party, length);
	}
	check_csw_message_keys(io.get(), party);
	cout << "\n";

	return 0;
}
