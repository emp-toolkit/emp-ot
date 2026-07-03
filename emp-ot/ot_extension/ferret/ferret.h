#ifndef EMP_FERRET_H_
#define EMP_FERRET_H_
#include "emp-ot/common/mp_gadget.h"
#include "emp-ot/ot_extension/ot_extension.h"
#include "emp-ot/base_ot/csw.h"
#include "emp-ot/tuning.h"
#include <memory>

// Forward-declare ferret internals so the public header doesn't pull
// in the cGGM transitive closure.
// The .cpp #includes the real headers; std::unique_ptr<T> works with
// forward-declared T as long as the dtor is out-of-line (it is).

namespace emp {

// Default base OT for Ferret. Forwarded into the inner SoftSpoken<8>
// bootstrap (or the inner ferret_b10 in the tiered-bootstrap path).
// Change here to swap; OTExtension's contract just needs any
// malicious-secure (when malicious=true) OT.
using FerretBaseOT = CSW;

template <typename AuthValue, int d> class Lpn;

// Concrete AuthValue type for Ferret's RCOT case (F_2 RCOT with no
// per-tree val/mac structure). One block per leaf — no separate val
// field. This is the "carrier + ops" pattern: storage is the struct
// itself (single `block mac` field; layout-equivalent to block), and
// every field-arithmetic / chi-fold / LPN op is a static member.
//
// Wire-format traits:
//   kHasSecretSum=false  — receiver α-fills via the cGGM
//                          LSB-clear closure (XOR of all leaves
//                          XOR bit0_mask).
//   kClearLeafLSB=true   — cGGM build/eval mask the per-leaf LSB.
//   kChiFoldFlavor=F2kPacked
//                        — Δ-XOR on chi-check region + Galois pack.
struct AuthValueFerret {
  using F = block;
  F mac;   // sole storage; layout-equivalent to `block`.

  // -------- Field arithmetic --------
  // Only f_zero / f_add are needed for the F2kPacked path; f_mul /
  // f_sub live exclusively in the FTyped branches of mp_gadget.h
  // which AuthValueFerret never instantiates.
  static inline F f_zero()         { return zero_block; }
  static inline F f_add(F a, F b)  { return a ^ b; }

  // -------- Wire-format traits --------
  static constexpr bool          kHasSecretSum  = false;
  static constexpr bool          kClearLeafLSB  = true;
  static constexpr ChiFoldFlavor kChiFoldFlavor = ChiFoldFlavor::F2kPacked;

  // (No auth_from_block — AuthValueFerret is layout-equivalent to
  // `block`, so the gadget reinterprets directly when handing the
  // block-typed cGGM buffer to the AuthValueFerret-typed user-out.)

  // -------- Chi-fold helpers --------
  // PRG-expand the chi seed into chi[leave_n]. Differs from
  // AuthValueF2k / AuthValueFp (hash + uni_hash_coeff_gen) — Ferret's
  // MPCOT historically derives chi via PRG, and the round-final
  // hash bytes on the wire depend on the resulting VW, so this
  // expansion must be preserved verbatim.
  static inline void expand_chi(block chi_seed, F* chi, int64_t sz) {
    PRG chi_prg(&chi_seed);
    chi_prg.random_block(chi, sz);
  }

  // Galois inner product with deferred reduce: VW[idx] = Σ chi · mac.
  // leaves' single-field layout = block, so cast is well-defined.
  static inline void accumulate_VW(F& VW_slot, const F* chi,
                                   const AuthValueFerret* leaves,
                                   int64_t sz) {
    vector_inn_prdt_sum_red(&VW_slot, chi,
                            reinterpret_cast<const block*>(leaves), sz);
  }

  // -------- LPN ops (Lpn<AuthValueFerret, 10>) --------
  // F_2 is XOR-only — no carry concern, so partial/final reduce are
  // no-ops and the LPN can fold all d adds in one batch.
  static constexpr int kLpnSafeAddsPerReduce =
      std::numeric_limits<int>::max();
  static inline void auth_add_into(AuthValueFerret& acc,
                                   const AuthValueFerret& x) {
    acc.mac = acc.mac ^ x.mac;
  }
  static inline void auth_partial_reduce(AuthValueFerret&) {}
  static inline void auth_final_reduce  (AuthValueFerret&) {}
};

// Back-compat aliases over the unified gadget.
using MPCOT_Sender   = MultiPointGadgetSender<AuthValueFerret>;
using MPCOT_Receiver = MultiPointGadgetReceiver<AuthValueFerret>;

/*
 * Ferret COT binary version
 * [REF] Implementation of "Ferret: Fast Extension for coRRElated oT with small communication"
 * https://eprint.iacr.org/2020/924.pdf
 *
 * Single class for both roles; party-dispatched internally inside
 * begin / next / end and the per-tree helpers. Structurally parallel
 * to Svole<AuthValue> — both inherit StreamingExtension<> (Ferret
 * indirectly via OTExtension) and implement the same 4-step round
 * loop (bootstrap + ping-pong swap + tree counter + per-tree inner
 * gadget call → LPN slice → tree_idx_++ ; round-end refill + chi-fold
 * check).
 */
class Ferret : public OTExtension {
public:
	PrimalLPNParameter param;

	// `base_ot` is forwarded to the internal SoftSpoken<8> bootstrap.
	// Default (nullptr) → the base allocates an CSW.
	Ferret(int party, IOChannel *io, bool malicious = true,
			PrimalLPNParameter param = tuning::ferret_b13,
			std::unique_ptr<OT> base_ot = nullptr);

	~Ferret() override;

	// Override the base set_delta to also propagate Δ into the
	// sender-side mpcot state. Pre-bootstrap only.
	void set_delta(const bool *bits) override;

	// StreamingExtension contract. Each next() produces exactly
	// `chunk_size()` = 2^tree_depth RCOT outputs (one cGGM tree's
	// leaves). next() includes the auto-rollover check (transparent
	// end→begin when this round's user-visible budget is full).
	int64_t chunk_size() const override;         // = 2^tree_depth
	void begin() override;
	void next(block *out) override;
	void end() override;

	// Per-chunk extend (next()) traffic direction: the OT-sender role is
	// send-dominant per tree (MPCOT_Sender::run_next_tree sends the cGGM
	// correction + secret_sum), the receiver recv-dominant — the opposite of
	// SoftSpoken. Callers interleaving the COT with a fixed-direction protocol
	// on the same sockets read this to place the send-dominant role on the send
	// channel. (begin()'s nested-SoftSpoken bootstrap is recv-dominant, but
	// that is an isolated one-time bookend, not the per-chunk streaming path.)
	static constexpr bool kSenderSendsOnExtend = true;

protected:
	// Per-stage helpers, called from begin / next / end. Each
	// party-dispatches internally where the sender and receiver
	// bodies diverge. `protected` (not private) so SilentFerret can
	// reuse the bootstrap / buffers / LPN / round-end machinery and
	// override only the per-tree body. process_one_tree_ is virtual so
	// the inherited next() / run_refill_ dispatch to the override.
	void bootstrap_();
	void inner_run_begin_();
	virtual void process_one_tree_(AuthValueFerret *out);
	void inner_run_end_();
	void run_refill_();

	int64_t tree_idx_ = 0;

	// Per-Ferret-lifetime LPN-seed exchange state. The seed is
	// exchanged once on first do_begin (receiver derives from
	// choice_prg, sender receives), and lpn_'s PRG state advances
	// continuously from there.
	bool lpn_seed_set_ = false;

	// Two ping-pong base-COT buffers, each `refill_trees * 2^tree_depth`
	// blocks. curr_ holds the round's M base COTs (chi-check + LPN-secret +
	// cGGM-correction slots, see ferret.cpp for the layout); next_ is
	// written by this round's refill trees. Swapped at every round
	// boundary in do_begin. Element type is raw `block` (block
	// storage; reinterpret to AuthValueFerret at the gadget/Lpn boundary).
	BlockVec carry_curr_;
	BlockVec carry_next_;

	// Exactly one of these is populated, depending on `party`.
	std::unique_ptr<MPCOT_Sender>            gadget_send_;
	std::unique_ptr<MPCOT_Receiver>          gadget_recv_;
	std::unique_ptr<Lpn<AuthValueFerret, 10>> lpn_;
};

}  // namespace emp
#endif  // EMP_FERRET_COT_H_
