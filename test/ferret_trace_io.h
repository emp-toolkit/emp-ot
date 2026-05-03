#ifndef FERRET_TRACE_IO_H__
#define FERRET_TRACE_IO_H__

#include "emp-tool/emp-tool.h"
#include <cstdio>
#include <cstdint>
#include <string>

namespace emp {

// Test-only wrapper around an IOChannel that forwards every send/recv
// to the underlying transport AND mirrors the bytes into a trace file
// as `(direction:1B, length:8B, payload:length B)` records. Used by
// test_ferret_trace to byte-diff before/after-refactor wire traffic.
class TraceIO : public IOChannel {
public:
    TraceIO(IOChannel* base, const std::string& path) : base_(base) {
        out_ = std::fopen(path.c_str(), "wb");
        if (!out_) error("trace file open failed");
    }
    ~TraceIO() override {
        if (out_) std::fclose(out_);
    }

    void send_data_internal(const void* data, size_t nbyte) override {
        write_record('S', data, nbyte);
        base_->send_data_internal(data, nbyte);
    }
    void recv_data_internal(void* data, size_t nbyte) override {
        base_->recv_data_internal(data, nbyte);
        write_record('R', data, nbyte);
    }
    void flush() override { base_->flush(); }
    void sync()  override { base_->sync(); }

private:
    void write_record(char dir, const void* data, size_t nbyte) {
        uint64_t len = nbyte;
        std::fwrite(&dir, 1, 1, out_);
        std::fwrite(&len, sizeof(len), 1, out_);
        std::fwrite(data, 1, nbyte, out_);
    }

    IOChannel* base_;
    FILE* out_ = nullptr;
};

}  // namespace emp
#endif
