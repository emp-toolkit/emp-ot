#include "emp-ot/emp-ot.h"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <type_traits>
#include <utility>
#include <vector>

using namespace emp;

namespace {

template <typename F>
bool expect_rejected(const char *label, const char *message, F &&fn) {
    int stderr_pipe[2];
    if (pipe(stderr_pipe) != 0) {
        std::cerr << label << ": pipe failed: " << std::strerror(errno) << '\n';
        return false;
    }

    const pid_t pid = fork();
    if (pid == 0) {
        close(stderr_pipe[0]);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stderr_pipe[1]);
        setvbuf(stderr, nullptr, _IONBF, 0);
        alarm(3);
        std::forward<F>(fn)();
        _exit(0);
    }
    close(stderr_pipe[1]);
    if (pid < 0) {
        close(stderr_pipe[0]);
        std::cerr << label << ": fork failed: " << std::strerror(errno) << '\n';
        return false;
    }

    std::string diagnostic;
    char buf[256];
    for (;;) {
        const ssize_t got = read(stderr_pipe[0], buf, sizeof(buf));
        if (got > 0) {
            diagnostic.append(buf, static_cast<size_t>(got));
            continue;
        }
        if (got < 0 && errno == EINTR) continue;
        break;
    }
    close(stderr_pipe[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) != pid) {
        std::cerr << label << ": waitpid failed\n";
        return false;
    }
    const bool exited_as_contract =
        WIFEXITED(status) && WEXITSTATUS(status) == 1;
    const bool has_message = diagnostic.find(message) != std::string::npos;
    if (!exited_as_contract || !has_message) {
        std::cerr << label << ": expected exit 1 containing \"" << message
                  << "\", status=" << status << ", stderr=\"" << diagnostic
                  << "\"\n";
        return false;
    }
    return true;
}

class FakeStreaming final : public StreamingExtension<uint64_t> {
public:
    explicit FakeStreaming(int64_t chunk)
        : StreamingExtension<uint64_t>(ALICE, false), chunk_(chunk) {}

    int64_t chunk_size() const override { return chunk_; }
    void begin() override { enter_session_(); }
    void next(uint64_t *out) override {
        expect_in_session_();
        for (int64_t i = 0; i < chunk_; ++i) out[i] = counter_++;
    }
    void end() override {
        expect_in_session_();
        exit_session_();
    }

private:
    int64_t chunk_;
    uint64_t counter_ = 0;
};

class SizedFakeStreaming final : public StreamingExtension<uint64_t> {
public:
    SizedFakeStreaming() : StreamingExtension<uint64_t>(ALICE, false) {}

    int64_t chunk_size() const override { return 4; }
    void begin_counted_for_test(int64_t n) { begin_counted_(n); }
    void begin() override { enter_session_(); }
    void next(uint64_t *out) override {
        expect_in_session_();
        ++full_calls;
        fill_(out, 4);
    }
    void end() override {
        expect_in_session_();
        exit_session_();
    }

    int64_t full_calls = 0;
    int64_t sized_calls = 0;
    int64_t last_sized_request = 0;

protected:
    int64_t next_sized_tail_(uint64_t *out, int64_t requested) override {
        expect_in_session_();
        ++sized_calls;
        last_sized_request = requested;
        fill_(out, requested);
        return requested;
    }

private:
    void fill_(uint64_t *out, int64_t n) {
        for (int64_t i = 0; i < n; ++i) out[i] = counter_++;
    }

    uint64_t counter_ = 0;
};

class DummyOT final : public OT {
public:
    explicit DummyOT(bool secure) : secure_(secure) {}
    void send(const block *, const block *, int64_t) override {}
    void recv(block *, const bool *, int64_t) override {}
    bool is_malicious_secure() const override { return secure_; }

private:
    bool secure_;
};

class DummyExtension final : public OTExtension {
public:
    DummyExtension(int party, bool malicious, std::unique_ptr<OT> base)
        : OTExtension(party, nullptr, malicious, std::move(base)) {}

    using OTExtension::begin;
    int64_t chunk_size() const override { return 1; }
    void begin() override { enter_session_(); }
    void next(block *out) override {
        expect_in_session_();
        *out = zero_block;
    }
    void end() override {
        expect_in_session_();
        exit_session_();
    }
    void mark_setup_done() { setup_done = true; }
};

class FixedInputIO final : public IOChannel {
public:
    FixedInputIO(const uint8_t *input, int64_t size)
        : input_(input), size_(size) {}

    void send_data_internal(const void *, int64_t) override {}
    void recv_data_internal(void *out, int64_t nbyte) override {
        expecting(nbyte >= 0 && offset_ >= 0 && offset_ <= size_ &&
                      nbyte <= size_ - offset_,
                  "FixedInputIO: insufficient input");
        std::memcpy(out, input_ + offset_, static_cast<size_t>(nbyte));
        offset_ += nbyte;
    }

private:
    const uint8_t *input_;
    int64_t size_;
    int64_t offset_ = 0;
};

// Scripted input plus a record of what was sent, with ordering gates. A send
// gate {at, need} lets output bytes from offset `at` on leave only after
// `need` input bytes have been read; a receive gate {at, need} lets input
// bytes from offset `at` on be read only after `need` bytes were sent. A
// violated gate, or a send past `cap` bytes, ends the process with status 2,
// which a rejection test reports as a failure, not as the rejection.
class ScriptIO final : public IOChannel {
public:
    struct Gate { int64_t at, need; };
    ScriptIO(std::vector<uint8_t> input, int64_t cap,
             std::vector<Gate> send_gates, std::vector<Gate> recv_gates)
        : input_(std::move(input)), cap_(cap),
          send_gates_(std::move(send_gates)), recv_gates_(std::move(recv_gates)) {}

    std::vector<uint8_t> sent;

    void send_data_internal(const void *data, int64_t nbyte) override {
        const int64_t at = static_cast<int64_t>(sent.size());
        if (at + nbyte > cap_) die("sent past its cap");
        for (const Gate &g : send_gates_)
            if (at + nbyte > g.at && received_ < g.need)
                die("sent before the input it waits for");
        const uint8_t *b = static_cast<const uint8_t *>(data);
        sent.insert(sent.end(), b, b + nbyte);
    }
    void recv_data_internal(void *out, int64_t nbyte) override {
        expecting(nbyte >= 0 &&
                      received_ + nbyte <= static_cast<int64_t>(input_.size()),
                  "ScriptIO: insufficient input");
        for (const Gate &g : recv_gates_)
            if (received_ + nbyte > g.at &&
                static_cast<int64_t>(sent.size()) < g.need)
                die("read before the output it waits for");
        std::memcpy(out, input_.data() + received_, static_cast<size_t>(nbyte));
        received_ += nbyte;
    }

private:
    [[noreturn]] static void die(const char *what) {
        std::fprintf(stderr, "ScriptIO: %s\n", what);
        std::fflush(stderr);
        _exit(2);
    }
    std::vector<uint8_t> input_;
    int64_t cap_;
    std::vector<Gate> send_gates_, recv_gates_;
    int64_t received_ = 0;
};

template <typename T>
void append_bytes(std::vector<uint8_t> &out, const T &v) {
    const uint8_t *b = reinterpret_cast<const uint8_t *>(&v);
    out.insert(out.end(), b, b + sizeof(T));
}

bool check_zero_count_semantics() {
    FakeStreaming stream(4);
    stream.run(nullptr, 0);

    uint64_t first = 0;
    stream.run(&first, 1);
    stream.run(nullptr, 0);
    uint64_t tail[3] = {};
    stream.run(tail, 3);
    if (first != 0 || tail[0] != 1 || tail[1] != 2 || tail[2] != 3)
        return false;

    stream.begin();
    stream.next_n(nullptr, 0);
    uint64_t next = 0;
    stream.next_n(&next, 1);
    stream.end();
    return next == 4;
}

bool check_counted_begin_semantics() {
    SizedFakeStreaming stream;
    uint64_t counted[3] = {};
    stream.begin_counted_for_test(3);
    stream.next_n(counted, 1);
    stream.next_n(counted + 1, 2);
    stream.end();
    if (counted[0] != 0 || counted[1] != 1 || counted[2] != 2 ||
        stream.sized_calls != 1 || stream.last_sized_request != 3 ||
        stream.full_calls != 0)
        return false;

    // An ordinary (uncounted) begin() session refills a full chunk.
    uint64_t ordinary = 0;
    stream.begin();
    stream.next_n(&ordinary, 1);
    stream.end();
    return ordinary == 3 && stream.sized_calls == 1 &&
           stream.full_calls == 1;
}

}  // namespace

int main() {
    bool ok = check_zero_count_semantics() && check_counted_begin_semantics();
    uint64_t word = 0;

    constexpr PrimalLPNParameter tiny_svole_param(2, 0, 8);
    {
        FpVOLE<> fp(ALICE, nullptr, false, tiny_svole_param);
        const uint64_t delta = fp.delta();
        if (delta == 0 || delta >= AuthValueFp::PR_VAL) {
            std::cerr << "Fp default delta is not canonical and nonzero\n";
            ok = false;
        }
    }
    ok &= expect_rejected("Fp zero delta", "canonical nonzero", [&] {
        FpVOLE<> fp(ALICE, nullptr, false, tiny_svole_param);
        fp.set_delta(0);
    });
    ok &= expect_rejected("Fp noncanonical delta", "canonical nonzero", [&] {
        FpVOLE<> fp(ALICE, nullptr, false, tiny_svole_param);
        fp.set_delta(AuthValueFp::PR_VAL);
    });

    ok &= expect_rejected("run negative", "negative element count", [&] {
        FakeStreaming stream(4);
        stream.run(&word, -1);
    });
    ok &= expect_rejected("run negative with leftover", "negative element count", [&] {
        FakeStreaming stream(4);
        stream.run(&word, 1);
        stream.run(&word, -1);
    });
    ok &= expect_rejected("run null", "null output", [] {
        FakeStreaming stream(4);
        stream.run(nullptr, 1);
    });
    ok &= expect_rejected("run byte overflow", "byte count overflow", [&] {
        FakeStreaming stream(4);
        stream.run(&word, std::numeric_limits<int64_t>::max());
    });
    ok &= expect_rejected("zero chunk", "chunk size must be positive", [&] {
        FakeStreaming stream(0);
        stream.run(&word, 1);
    });
    ok &= expect_rejected("double begin", "previous session not ended", [] {
        FakeStreaming stream(4);
        stream.begin();
        stream.begin();
    });
    ok &= expect_rejected("counted begin negative", "negative element count", [] {
        DummyExtension extension(
            ALICE, false, std::make_unique<DummyOT>(false));
        extension.begin(-1);
    });
    ok &= expect_rejected("counted begin byte overflow", "byte count overflow", [] {
        DummyExtension extension(
            ALICE, false, std::make_unique<DummyOT>(false));
        extension.begin(std::numeric_limits<int64_t>::max());
    });
    ok &= expect_rejected("end before begin", "no active session", [] {
        FakeStreaming stream(4);
        stream.end();
    });
    ok &= expect_rejected("next before begin", "no active session", [&] {
        FakeStreaming stream(4);
        stream.next(&word);
    });
    ok &= expect_rejected("next_n before begin", "call begin first", [&] {
        FakeStreaming stream(4);
        stream.next_n(&word, 1);
    });
    ok &= expect_rejected("check before begin", "no active session", [] {
        DummyExtension extension(
            ALICE, false, std::make_unique<DummyOT>(false));
        extension.check();
    });
    ok &= expect_rejected("next_n negative", "negative element count", [&] {
        FakeStreaming stream(4);
        stream.begin();
        stream.next_n(&word, -1);
    });
    ok &= expect_rejected("next_n null", "null output", [] {
        FakeStreaming stream(4);
        stream.begin();
        stream.next_n(nullptr, 1);
    });
    ok &= expect_rejected("next_n exceeds declared count", "exceeds declared", [&] {
        DummyExtension extension(
            ALICE, false, std::make_unique<DummyOT>(false));
        block out[2];
        extension.begin(1);
        extension.next_n(out, 2);
    });
    ok &= expect_rejected("run during session", "active streaming session", [&] {
        FakeStreaming stream(4);
        stream.begin();
        stream.run(&word, 1);
    });
    ok &= expect_rejected("destroy during session", "without calling end", [] {
        auto stream = std::make_unique<FakeStreaming>(4);
        stream->begin();
    });

    bool bits[128] = {};
    bits[0] = true;
    {
        DummyExtension extension(
            ALICE, true, std::make_unique<DummyOT>(true));
    }
    ok &= expect_rejected("null base OT", "non-null base_ot", [] {
        DummyExtension extension(ALICE, false, nullptr);
    });
    ok &= expect_rejected("insecure malicious base OT", "malicious-secure base OT", [] {
        DummyExtension extension(ALICE, true, std::make_unique<DummyOT>(false));
    });
    ok &= expect_rejected("receiver set_delta", "receiver has no", [&] {
        DummyExtension extension(BOB, false, std::make_unique<DummyOT>(false));
        extension.set_delta(bits);
    });
    ok &= expect_rejected("null delta", "null bit buffer", [] {
        DummyExtension extension(ALICE, false, std::make_unique<DummyOT>(false));
        extension.set_delta(nullptr);
    });
    ok &= expect_rejected("even delta", "bits[0] must be true", [] {
        DummyExtension extension(ALICE, false, std::make_unique<DummyOT>(false));
        bool even_bits[128] = {};
        extension.set_delta(even_bits);
    });
    ok &= expect_rejected("late delta", "bootstrap already fired", [&] {
        DummyExtension extension(ALICE, false, std::make_unique<DummyOT>(false));
        extension.mark_setup_done();
        extension.set_delta(bits);
    });
    ok &= expect_rejected("late sid", "bootstrap already fired", [] {
        DummyExtension extension(BOB, false, std::make_unique<DummyOT>(false));
        extension.mark_setup_done();
        extension.set_sid(makeBlock(0x1a7e, 1));
    });
    // Every object runs under a nonzero session id, set explicitly or drawn
    // from a channel with a session root; a channel without one needs set_sid.
    ok &= expect_rejected("zero sid", "the session id is zero", [] {
        DummyExtension extension(BOB, false, std::make_unique<DummyOT>(false));
        extension.set_sid(SessionID{});
    });
    ok &= expect_rejected("zero sVOLE sid", "the session id is zero", [] {
        F2kVOLE<> vole(ALICE, nullptr, false, tuning::ferret_b9);
        vole.set_sid(SessionID{});
    });
    ok &= expect_rejected("OT on a channel without a session root",
                          "no session id", [] {
        FixedInputIO io(nullptr, 0);
        CO co(&io);
        block data0[1] = {zero_block};
        block data1[1] = {zero_block};
        co.send(data0, data1, 1);
    });
    ok &= expect_rejected("sVOLE on a channel without a session root",
                          "no session id", [] {
        FixedInputIO io(nullptr, 0);
        F2kVOLE<> vole(ALICE, &io, false, tuning::ferret_b9);
        vole.begin();
    });
    {
        const block seed = zero_block;
        Ferret receiver(BOB, nullptr, false, std::make_unique<DummyOT>(false),
                        tuning::ferret_b9);
        receiver.set_choice_seed(&seed, zero_block);
        Ferret sender(ALICE, nullptr, false, std::make_unique<DummyOT>(false),
                      tuning::ferret_b9);
        sender.set_choice_seed(nullptr, zero_block);
    }
    ok &= expect_rejected("sender choice seed", "the sender has no choice bits", [] {
        const block seed = zero_block;
        Ferret ferret(ALICE, nullptr, false, std::make_unique<DummyOT>(false),
                      tuning::ferret_b9);
        ferret.set_choice_seed(&seed, zero_block);
    });
    ok &= expect_rejected("receiver without a choice seed", "the receiver needs a choice seed", [] {
        Ferret ferret(BOB, nullptr, false, std::make_unique<DummyOT>(false),
                      tuning::ferret_b9);
        ferret.set_choice_seed(nullptr, zero_block);
    });
    ok &= expect_rejected("late choice seed", "bootstrap already fired", [] {
        const block seed = zero_block;
        Ferret ferret(BOB, nullptr, false, std::make_unique<DummyOT>(false),
                      tuning::ferret_b9);
        ferret.setup_done = true;
        ferret.set_choice_seed(&seed, zero_block);
    });
    ok &= expect_rejected("receiver wrapper on a sender", "this extension is the sender", [] {
        DummyExtension extension(ALICE, false, std::make_unique<DummyOT>(false));
        block out[1];
        bool b[1] = {true};
        extension.recv_cot(out, b, 1);
    });
    ok &= expect_rejected("sender wrapper on a receiver", "this extension is the receiver", [] {
        DummyExtension extension(BOB, false, std::make_unique<DummyOT>(false));
        block out[1];
        extension.send_cot(out, 1);
    });
    ok &= expect_rejected("clone before bootstrap", "parent not bootstrapped", [] {
        SoftSpoken<8> parent(BOB, nullptr, false, std::make_unique<DummyOT>(false));
        auto lane = parent.clone_lane(nullptr);
    });
    ok &= expect_rejected("clone before base check", "deferred base-OT check has not run", [] {
        SoftSpoken<8> parent(BOB, nullptr, false, std::make_unique<DummyOT>(false));
        parent.setup_done = true;            // as after bootstrap over CSW,
        parent.base_check_pending_ = true;   // before the first end()/check()
        auto lane = parent.clone_lane(nullptr);
    });
    ok &= expect_rejected("CSW send security bound", "length must be", [] {
        CSW csw(nullptr);
        csw.send_core(nullptr, nullptr, 79);
    });
    ok &= expect_rejected("CSW recv security bound", "length must be", [] {
        CSW csw(nullptr);
        csw.recv_core(nullptr, nullptr, 79);
    });
    ok &= expect_rejected("BMM negative length", "invalid length or null buffer", [] {
        BMM bmm(nullptr);
        bmm.send(nullptr, nullptr, -1);
    });
    // One receiver first-flow payload: r (768 / 1152 / 1536 bytes) followed
    // by c_0, c_1. Encode coefficient 3329 (= q) in the first 12-bit slot;
    // every canonical R_q coefficient must instead be in [0,3329).
    auto noncanonical_r = [](auto bmm_tag, auto flow_bytes) {
        return [] {
            using BMMx = typename decltype(bmm_tag)::type;
            std::array<uint8_t, decltype(flow_bytes)::value> first_flow = {};
            first_flow[0] = 0x01;
            first_flow[1] = 0x0d;
            FixedInputIO io(first_flow.data(), static_cast<int64_t>(first_flow.size()));
            BMMx bmm(&io);
            bmm.set_sid(makeBlock(0xb33, 1));
            block data0[1] = {zero_block};
            block data1[1] = {zero_block};
            bmm.send(data0, data1, 1);
        };
    };
    ok &= expect_rejected("BMM noncanonical r", "noncanonical r encoding",
                          noncanonical_r(std::type_identity<BMM>{},
                                         std::integral_constant<size_t, 832>{}));
    ok &= expect_rejected("BMM768 noncanonical r", "noncanonical r encoding",
                          noncanonical_r(std::type_identity<BMM768>{},
                                         std::integral_constant<size_t, 1216>{}));
    ok &= expect_rejected("BMM1024 noncanonical r", "noncanonical r encoding",
                          noncanonical_r(std::type_identity<BMM1024>{},
                                         std::integral_constant<size_t, 1600>{}));
    ok &= expect_rejected("invalid BaseOtKind", "invalid BaseOtKind", [] {
        (void)make_base_ot(static_cast<BaseOtKind>(255), nullptr);
    });
    ok &= expect_rejected("negative LPN logk", "logk must be", [] {
        (void)PrimalLPNParameter(100, -1, 10);
    });
    ok &= expect_rejected("oversized LPN tree depth", "tree_depth must be", [] {
        (void)PrimalLPNParameter(100, 10, 31);
    });
    ok &= expect_rejected("LPN tree depth 1", "tree_depth must be in [2, 30]", [] {
        (void)PrimalLPNParameter(100, 10, 1);
    });
    ok &= expect_rejected("LPN M overflow", "M overflows", [] {
        (void)PrimalLPNParameter(std::numeric_limits<int64_t>::max(), 0, 2);
    });
    ok &= expect_rejected("LPN output overflow", "round output size overflows", [] {
        (void)PrimalLPNParameter(
            std::numeric_limits<int64_t>::max() / 4 + 1, 0, 2);
    });
    ok &= expect_rejected("FpVOLE set beyond the pre-stage", "more carry pairs", [] {
        FixedInputIO io(nullptr, 0);
        FpVOLE<> vole(ALICE, &io, /*malicious=*/true,
                      PrimalLPNParameter(200, 21, 14));
        vole.set_sid(makeBlock(0xf9, 1));
        vole.begin();
    });

    // F_p elements from the peer must be canonical (< p): p - 1 is read as is,
    // p and 2^64 - 1 (encodings of the residues 0 and 7) abort.
    {
        const uint64_t top = AuthValueFp::PR_VAL - 1;
        FixedInputIO io(reinterpret_cast<const uint8_t *>(&top), sizeof(top));
        uint64_t got = 0;
        recv_fp(&io, &got, 1);
        if (got != top) {
            std::cerr << "recv_fp changed a canonical element\n";
            ok = false;
        }
    }
    for (const uint64_t bad : {AuthValueFp::PR_VAL, ~uint64_t{0}}) {
        ok &= expect_rejected("Fp non-canonical receive",
                              "non-canonical F_p element", [bad] {
            FixedInputIO io(reinterpret_cast<const uint8_t *>(&bad), sizeof(bad));
            uint64_t got;
            recv_fp(&io, &got, 1);
        });
    }
    // The multi-point gadget's received F values: the sender's x* and the
    // receiver's per-tree secret_sum.
    ok &= expect_rejected("Fp gadget non-canonical x*",
                          "non-canonical field element", [] {
        const uint64_t x_star = AuthValueFp::PR_VAL;
        FixedInputIO io(reinterpret_cast<const uint8_t *>(&x_star), sizeof(x_star));
        MultiPointGadgetSender<AuthValueFp> gadget(1, 1, &io);
        gadget.set_malicious();
        gadget.set_delta(1);
        gadget.run_begin();
        gadget.run_end_typed(AuthValueFp{0, 0});
    });
    ok &= expect_rejected("Fp gadget non-canonical secret_sum",
                          "non-canonical field element", [] {
        // One tree of depth 1 on the wire: one correction block, then secret_sum.
        std::array<uint8_t, sizeof(block) + sizeof(uint64_t)> wire = {};
        const uint64_t secret_sum = AuthValueFp::PR_VAL;
        std::memcpy(wire.data() + sizeof(block), &secret_sum, sizeof(secret_sum));
        FixedInputIO io(wire.data(), static_cast<int64_t>(wire.size()));
        MultiPointGadgetReceiver<AuthValueFp> gadget(1, 1, &io);
        gadget.run_begin();
        AuthValueFp leaves[2];
        const block base = zero_block;
        gadget.run_next_tree(leaves, &base, 0, 0);
    });

    // The typed check's equality test (F_p carrier, one tree, no trees run, so
    // the check values are the mask's mac). The Δ-holder reads x*, sends its
    // commitment (32 bytes), reads va, and only on a match sends the salt;
    // the receiver sends x*, reads the commitment, sends va, reads the salt.
    {
        const block sid = makeBlock(0x5e, 0x1d);
        const AuthValueFp mask{7, 99};   // val, mac
        constexpr int64_t kCom = 2 * sizeof(block);
        constexpr int64_t kF = sizeof(uint64_t);
        auto holder_io = [&](uint64_t va, int64_t cap) {
            std::vector<uint8_t> in;
            append_bytes(in, uint64_t{0});   // x*
            append_bytes(in, va);
            // commitment after x*, salt after va; va read only after the commitment
            return ScriptIO(std::move(in), cap, {{0, kF}, {kCom, 2 * kF}}, {{kF, kCom}});
        };
        auto holder = [&](ScriptIO &io) {
            MultiPointGadgetSender<AuthValueFp> gadget(1, 1, &io);
            gadget.sid = sid;
            gadget.set_malicious();
            gadget.set_delta(12345);
            gadget.run_begin();
            gadget.run_end_typed(mask);
        };
        {   // match: the holder opens, and the opening verifies
            ScriptIO io = holder_io(mask.mac, kCom + sizeof(block));
            holder(io);
            block com[2], salt, opened[2];
            const bool sizes = io.sent.size() == kCom + sizeof(block);
            if (sizes) {
                std::memcpy(com, io.sent.data(), kCom);
                std::memcpy(&salt, io.sent.data() + kCom, sizeof(block));
                typed_check_commit(sid, mask.mac, salt, opened);
            }
            if (!sizes || !cmpBlock(com, opened, 2)) {
                std::cerr << "typed check: the holder's opening does not verify\n";
                ok = false;
            }
        }
        // mismatch: the holder aborts, and its salt never leaves (cap = commitment)
        ok &= expect_rejected("typed check holder mismatch", "chi-fold check failed", [&] {
            ScriptIO io = holder_io(mask.mac + 1, kCom);
            holder(io);
        });

        auto receiver_io = [&](const block com[2], block salt) {
            std::vector<uint8_t> in;
            append_bytes(in, com[0]);
            append_bytes(in, com[1]);
            append_bytes(in, salt);
            // va leaves only after the commitment arrived
            return ScriptIO(std::move(in), 2 * kF, {{kF, kCom}}, {{kCom, 2 * kF}});
        };
        auto receiver = [&](ScriptIO &io) {
            MultiPointGadgetReceiver<AuthValueFp> gadget(1, 1, &io);
            gadget.sid = sid;
            gadget.set_malicious();
            gadget.run_begin();
            const AuthValueFp triples[1] = {AuthValueFp{3, 4}};
            gadget.run_end_typed(triples, mask);
        };
        const block salt = makeBlock(0xabc, 0xdef);
        {   // a valid opening is accepted; x* is the mask's val, va its mac
            block com[2];
            typed_check_commit(sid, mask.mac, salt, com);
            ScriptIO io = receiver_io(com, salt);
            receiver(io);
            uint64_t sent[2] = {0, 0};
            const bool sizes = io.sent.size() == 2 * kF;
            if (sizes) std::memcpy(sent, io.sent.data(), 2 * kF);
            if (!sizes || sent[0] != mask.val || sent[1] != mask.mac) {
                std::cerr << "typed check: the receiver sent the wrong x* or va\n";
                ok = false;
            }
        }
        ok &= expect_rejected("typed check bad opening", "chi-fold check failed", [&] {
            block com[2];
            typed_check_commit(sid, mask.mac + 1, salt, com);
            ScriptIO io = receiver_io(com, salt);
            receiver(io);
        });
    }

    if (!ok) return 1;
    std::cout << "test_contracts: OK\n";
    return 0;
}
