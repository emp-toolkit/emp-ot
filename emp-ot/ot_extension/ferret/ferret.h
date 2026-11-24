#ifndef EMP_FERRET_H_
#define EMP_FERRET_H_
#include "emp-ot/common/mp_gadget.h"
#include "emp-ot/common/table_alloc.h"
#include "emp-ot/ot_extension/ot_extension.h"
#include "emp-ot/base_ot/csw.h"
#include "emp-ot/tuning.h"
#include <memory>

// Forward-declare Lpn so the public header doesn't pull in lpn.h. The
// .cpp #includes it; std::unique_ptr<T> works with forward-declared T
// as long as the dtor is out-of-line (it is).

namespace emp {

// Default base OT for Ferret. Forwarded into the inner SoftSpoken<8>
// bootstrap (or the inner ferret_b9 in the tiered-bootstrap path).
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
  // PRG-expand the chi seed into chi[leave_n] (AuthValueF2k and
  // AuthValueFp mirror it). The round-final hash bytes on the wire
  // depend on the resulting VW, so this expansion is fixed by the wire
  // format.
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

// Ferret's names for its two gadget instantiations.
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
	// Default (nullptr) → a FerretBaseOT (CSW). The optional final
	// parameter selects the Ferret LPN parameter set (default ferret_b12).
	Ferret(int party, IOChannel *io, bool malicious = true,
			std::unique_ptr<OT> base_ot = nullptr,
			PrimalLPNParameter param = tuning::ferret_b12);

	~Ferret() override;

	// Override the base set_delta to also propagate Δ into the
	// sender-side mpcot state. Pre-bootstrap only.
	void set_delta(const bool *bits) override;

	// Set the session id, pre-bootstrap. Unlike OTExtension::set_sid this
	// forwards nothing to base_ot: the bootstrap moves base_ot into a nested
	// extension (SoftSpoken<8>, or a nested ferret_b9 that moves it on to its
	// own SoftSpoken<8>) under a derived child sid, and the SoftSpoken<8>
	// that runs the base OT sets the base OT's sid, once.
	void set_sid(SessionID s) override;

	// Seeded choices, for a receiver that needs one set of choice bits under
	// several senders' Δs. Instances whose receivers hold the same choice seed,
	// and that share the LPN seed and the parameter set, give the same choice
	// bit at each position of their output streams, provided they are drawn
	// alike (the same begin() / begin(n_ots) / end() sequence). Both ends call
	// this before the first begin(): the receiver passes its secret seed, the
	// sender nullptr, and both the same public `lpn_seed`, which takes the place
	// of the session id in the LPN matrix. It changes the wire.
	//
	// Only the choice bits are shared. The bootstrap's SoftSpoken runs on its
	// own randomness and delivers the base through cot, with the seeded bits as
	// the receiver's choices (one correction bit per base COT), at the bottom of
	// the bootstrap only (the nested ferret_b9 for the sets that nest). Every later base comes from the
	// refill trees, whose choice bits follow. In malicious mode each consistency
	// check is masked by 128 COTs that the same SoftSpoken extends just before
	// that check, never by base COTs, which the instances share; the SoftSpoken
	// therefore lives as long as this object. Every message the receiver sends
	// is thus padded by randomness of its own instance.
	void set_choice_seed(const block *choice_seed, const block &lpn_seed);

	// StreamingExtension contract. Each next() produces exactly
	// `chunk_size()` = 2^tree_depth RCOT outputs (one cGGM tree's
	// leaves). next() includes the auto-rollover check (transparent
	// end→begin when this round's user-visible budget is full).
	using OTExtension::begin;
	int64_t chunk_size() const override;         // = 2^tree_depth
	void begin() override;
	void next(block *out) override;
	void end() override;

	// Per-chunk extend (next()) traffic direction: the OT-sender role is
	// send-dominant per tree (MPCOT_Sender::run_next_tree sends the cGGM
	// correction), the receiver recv-dominant — the opposite of
	// SoftSpoken. Callers interleaving the COT with a fixed-direction protocol
	// on the same sockets read this to place the send-dominant role on the send
	// channel. (begin()'s nested-SoftSpoken bootstrap is recv-dominant, but
	// that is an isolated one-time bookend, not the per-chunk streaming path.)
	static constexpr bool kSenderSendsOnExtend = true;

protected:
	// Per-stage helpers, called from begin / next / end. Each
	// party-dispatches internally where the sender and receiver
	// bodies diverge. `protected` (not private) so SilentFerret can
	// reuse the bootstrap / buffers / gadget / LPN machinery. It
	// overrides the lifecycle and process_one_tree_, and uses its own
	// base roll and batched check instead of run_refill_ / inner_run_end_.
	void bootstrap_();
	void inner_run_begin_();
	virtual void process_one_tree_(AuthValueFerret *out);
	void inner_run_end_();
	void run_refill_();

	// Seeded choices (set_choice_seed). Malicious mode only: fill `mask128`
	// with 128 COTs freshly extended by the bootstrap's SoftSpoken, for the
	// consistency check about to run.
	void draw_check_masks_(block *mask128);

	int64_t tree_idx_ = 0;

	// Per-Ferret-lifetime public LPN-matrix seed state: both roles derive the
	// seed at the first begin(), from the shared transcript sid or, with seeded
	// choices, from lpn_root_; lpn_'s PRG state advances continuously after
	// that.
	bool lpn_seed_set_ = false;

	// Seeded choices: choice_seed_ (receiver only, secret) and lpn_root_
	// (public). mask_src_ is the bootstrap's SoftSpoken in malicious mode, kept
	// for draw_check_masks_; null otherwise.
	bool seeded_ = false;
	block choice_seed_ = zero_block;
	block lpn_root_ = zero_block;
	std::unique_ptr<OTExtension> mask_src_;

	// Two ping-pong base-COT buffers, each `refill_trees * 2^tree_depth`
	// blocks. curr_ holds the round's M base COTs (chi-check + LPN-secret +
	// cGGM-correction slots, see ferret.cpp for the layout); next_ is
	// written by this round's refill trees. Swapped at every round
	// boundary in begin(). Element type is raw `block` (block
	// storage; reinterpret to AuthValueFerret at the gadget/Lpn boundary).
	// Line-aligned, and huge-page backed where the system allows it
	// (table_alloc.h).
	LpnTableBlockVec carry_curr_;
	LpnTableBlockVec carry_next_;

	// Exactly one of these is populated, depending on `party`.
	std::unique_ptr<MPCOT_Sender>            gadget_send_;
	std::unique_ptr<MPCOT_Receiver>          gadget_recv_;
	std::unique_ptr<Lpn<AuthValueFerret, 10>> lpn_;
};

}  // namespace emp
#endif  // EMP_FERRET_H_
