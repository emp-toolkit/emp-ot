#include "emp-ot/emp-ot.h"

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
#include <utility>

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

}  // namespace

int main() {
    bool ok = check_zero_count_semantics();
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
    ok &= expect_rejected("sender choice seed", "sender has no choice bits", [] {
        DummyExtension extension(ALICE, false, std::make_unique<DummyOT>(false));
        extension.set_choice_seed(zero_block);
    });
    ok &= expect_rejected("late choice seed", "bootstrap already fired", [] {
        DummyExtension extension(BOB, false, std::make_unique<DummyOT>(false));
        extension.mark_setup_done();
        extension.set_choice_seed(zero_block);
    });
    ok &= expect_rejected("late sid", "bootstrap already fired", [] {
        DummyExtension extension(BOB, false, std::make_unique<DummyOT>(false));
        extension.mark_setup_done();
        extension.set_sid(SessionID{});
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
    ok &= expect_rejected("invalid BaseOtKind", "invalid BaseOtKind", [] {
        (void)make_base_ot(static_cast<BaseOtKind>(255), nullptr);
    });
    ok &= expect_rejected("negative LPN logk", "logk must be", [] {
        (void)PrimalLPNParameter(100, -1, 10);
    });
    ok &= expect_rejected("oversized LPN tree depth", "tree_depth must be", [] {
        (void)PrimalLPNParameter(100, 10, 31);
    });
    ok &= expect_rejected("LPN M overflow", "M overflows", [] {
        (void)PrimalLPNParameter(std::numeric_limits<int64_t>::max(), 0, 1);
    });
    ok &= expect_rejected("LPN output overflow", "round output size overflows", [] {
        (void)PrimalLPNParameter(
            std::numeric_limits<int64_t>::max() / 2 + 1, 0, 1);
    });

    if (!ok) return 1;
    std::cout << "test_contracts: OK\n";
    return 0;
}
