#ifndef EMP_SOFTSPOKEN_SS_BENCH_PHASES_H__
#define EMP_SOFTSPOKEN_SS_BENCH_PHASES_H__

// Optional per-phase wall-clock instrumentation for the SoftSpoken chunk
// pipelines. Build with -DEMP_BENCH_PHASES to time each stage (butterfly /
// wire / derand / transpose / combine) per role and print a ns/OT
// breakdown to stderr at every session end(). Off by default: production
// builds compile every macro below to nothing and carry no timers. The
// scopes sit at section granularity (a handful of steady_clock reads per
// chunk), so instrumentation overhead is negligible relative to the
// timed work.
//
// Usage (softspoken.cpp):
//   { EMP_SS_PHASE(send, butterfly); ...section... }   scoped accumulation
//   EMP_SS_PHASE_OTS(send, n)                          count OTs produced
//   EMP_SS_PHASE_RESET(send) / EMP_SS_PHASE_REPORT(send)   at begin / end

#ifdef EMP_BENCH_PHASES
#include <chrono>
#include <cstdint>
#include <cstdio>

namespace emp { namespace softspoken { namespace phases {

struct Acc {
	uint64_t butterfly = 0, io = 0, derand = 0, transpose = 0, combine = 0;
	int64_t ots = 0;
	void reset() { *this = Acc{}; }
	void report(const char* role) {
		if (ots == 0) return;
		const double n = (double)ots;
		std::fprintf(stderr,
		    "[phases %s] ots=%lld  butterfly=%.3f io=%.3f derand=%.3f "
		    "transpose=%.3f combine=%.3f  (ns/OT; sum=%.3f)\n",
		    role, (long long)ots, butterfly / n, io / n, derand / n,
		    transpose / n, combine / n,
		    (butterfly + io + derand + transpose + combine) / n);
	}
};
inline Acc send_acc, recv_acc;

struct scope {
	uint64_t& acc;
	std::chrono::steady_clock::time_point t0;
	explicit scope(uint64_t& a) : acc(a), t0(std::chrono::steady_clock::now()) {}
	~scope() {
		acc += (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
		    std::chrono::steady_clock::now() - t0).count();
	}
};

}}}  // namespace emp::softspoken::phases

#define EMP_SS_PHASE(role, field) \
	emp::softspoken::phases::scope _ph_##field(emp::softspoken::phases::role##_acc.field)
#define EMP_SS_PHASE_OTS(role, n)   (emp::softspoken::phases::role##_acc.ots += (n))
#define EMP_SS_PHASE_RESET(role)    emp::softspoken::phases::role##_acc.reset()
#define EMP_SS_PHASE_REPORT(role)   emp::softspoken::phases::role##_acc.report(#role)

#else

#define EMP_SS_PHASE(role, field)   do {} while (0)
#define EMP_SS_PHASE_OTS(role, n)   do {} while (0)
#define EMP_SS_PHASE_RESET(role)    do {} while (0)
#define EMP_SS_PHASE_REPORT(role)   do {} while (0)

#endif  // EMP_BENCH_PHASES
#endif  // EMP_SOFTSPOKEN_SS_BENCH_PHASES_H__
