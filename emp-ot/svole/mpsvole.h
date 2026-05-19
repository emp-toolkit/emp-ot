#ifndef EMP_OT_SVOLE_MPSVOLE_H__
#define EMP_OT_SVOLE_MPSVOLE_H__

#include "emp-ot/ot_extension/cggm.h"
#include "emp-ot/svole/fp_utility.h"   // uni_hash_coeff_gen<T> for F_p paths
#include "emp-ot/svole/svole_extension.h"
#include <emp-tool/emp-tool.h>          // uni_hash_coeff_gen(block*, ...) for F2k

// Policy-templated multi-point sVOLE. Replaces both F2kMpsvole and
// FpMpsvole; the only differences between the F_2 and F_p cases are
// absorbed into the Policy:
//
//   - Policy::auth_from_block(block) → AuthValue
//       F2k: mac = block leaf as-is; val = zero_block.
//       Fp:  mac = mod p (low 64 of leaf); val = 0.
//   - Policy::hash_to_f(block digest) → F
//       F2k: identity (F = block).
//       Fp:  mod p (low 64 of digest).
//   - Policy::f_add / f_sub / f_mul / scalar_mul / embed / f_zero
//       Operate over the policy's field; the chi-fold algebra is
//       characteristic-agnostic in the F2k-style sign convention used
//       here (under F_2, f_sub = f_add = XOR, so the same formulas
//       collapse to the original F2k code).
//
// Two delta fields on the sender:
//   - cggm_delta (block): the F_2 sibling-OT correlation passed into
//     cGGM. For F2k, equal to the sVOLE Δ (both are blocks). For Fp,
//     equal to the owned Ferret's Δ, independent of the F_p sVOLE Δ.
//   - delta (F): the sVOLE Δ used inside the chi-fold algebra. F2k
//     and Fp callers each set both fields from the appropriate
//     source.
//
// Under cGGM + raw COT correlation, the sibling-OT layer collapses:
// sender ships c[j] = base[j] ^ K0[j]; receiver computes
// K_b[j] = c[j] ^ base_recv[j] and reads its choice bit
// b[j] = LSB(base_recv[j]).
//
// Malicious mode: per-tree chi seed from io->get_digest() (FS
// transcript), per-tree VW accumulated into consist_check_VW[tree_idx],
// round-final chi-fold consistency check in run_end.
//
// Chi-fold algebra (F2k convention; works for any characteristic):
//   sender:   vb = f_add(f_mul(delta, x_star), triple_t.mac) + Σ VW
//   receiver: x_star = f_add(Σ scalar_mul(triples[i].val, chi_alpha[i]),
//                            embed(triple_t.val));
//             va = triple_t.mac + Σ VW
//
// Honest-case correctness:
//   vb − va = δ·x_star − δ·(triple_t.val + Σ chi_alpha·triple_x) = 0
// since x_star = triple_t.val + Σ chi_alpha·triple_x by definition.

namespace emp {

// =================================================================
// MpsvoleSender — sender (Δ holder) side.
// =================================================================

template <typename Policy, typename IO> class MpsvoleSender {
public:
  using F = typename Policy::F;
  using AuthValue = typename Policy::AuthValue;

  IO *io;
  bool is_malicious = false;
  int64_t tree_n;        // = param.t
  int64_t tree_depth;    // = log_bin_sz
  int64_t leave_n;       // = 1 << tree_depth
  block cggm_delta;      // F_2 Δ for cGGM (= Ferret-issued block Δ).
  F delta;               // sVOLE Δ for chi-fold (= F-typed sVOLE Δ).
  PRG prg;
  std::vector<F> consist_check_VW;

  MpsvoleSender(int64_t t, int64_t tree_depth_in, IO *io)
      : io(io), tree_n(t), tree_depth(tree_depth_in),
        leave_n(int64_t{1} << tree_depth_in) {}

  void set_malicious() { is_malicious = true; }
  void set_cggm_delta(block d) { cggm_delta = d; }
  void set_delta(F d) { delta = d; }

  void run_begin() {
    if (is_malicious) consist_check_VW.assign(tree_n, Policy::f_zero());
  }

  // Per-tree:
  //   1. cggm::build_sender into block scratch + K0[tree_depth] (using
  //      cggm_delta as the cGGM Δ).
  //   2. extract block → AuthValue via Policy::auth_from_block,
  //      accumulate leaves_sum = Σ_F leaves[i].mac.
  //   3. ship c[] (tree_depth blocks) + secret_sum = gamma − leaves_sum
  //      (one F element on the wire).
  //   4. (malicious) chi seed via io->get_digest → hash_for_block →
  //      Policy::hash_to_f → uni_hash_coeff_gen; VW[tree_idx] =
  //      Σ chi[i] · leaves[i].mac.
  void run_next_tree(AuthValue *leaves_i, const block *base_i,
                     int tree_idx, F gamma_i) {
    block seed;
    prg.random_block(&seed, 1);
    std::vector<block> leaves_block(leave_n);
    std::vector<block> K0(tree_depth);
    cggm::build_sender<cggm::kTile, /*ClearLeafLSB=*/false>(
        tree_depth, cggm_delta, seed, leaves_block.data(), K0.data());

    std::vector<block> c(tree_depth);
    for (int64_t j = 0; j < tree_depth; ++j) c[j] = base_i[j] ^ K0[j];

    F leaves_sum = Policy::f_zero();
    for (int64_t i = 0; i < leave_n; ++i) {
      leaves_i[i] = Policy::auth_from_block(leaves_block[i]);
      leaves_sum = Policy::f_add(leaves_sum, leaves_i[i].mac);
    }
    F secret_sum = Policy::f_sub(gamma_i, leaves_sum);

    io->send_block(c.data(), tree_depth);
    io->send_data(&secret_sum, sizeof(F));
    io->flush();

    if (is_malicious) {
      block chi_seed = io->get_digest();
      Hash hash;
      block digest_b = hash.hash_for_block(&chi_seed, sizeof(block));
      F digest = Policy::hash_to_f(digest_b);
      std::vector<F> chi(leave_n);
      uni_hash_coeff_gen(chi.data(), digest, leave_n);
      F v = Policy::f_zero();
      for (int64_t i = 0; i < leave_n; ++i)
        v = Policy::f_add(v, Policy::f_mul(chi[i], leaves_i[i].mac));
      consist_check_VW[tree_idx] = v;
    }
  }

  // Round-final chi-fold (F2k-style universal convention):
  //   recv x_star;
  //   vb = δ·x_star + triple_t.mac + Σ VW;
  //   send hash(vb).
  void run_end(AuthValue triple_t) {
    if (!is_malicious) return;
    F x_star;
    io->recv_data(&x_star, sizeof(F));
    F vb = Policy::f_add(Policy::f_mul(delta, x_star), triple_t.mac);
    for (int64_t i = 0; i < tree_n; ++i)
      vb = Policy::f_add(vb, consist_check_VW[i]);

    Hash hash;
    block h = hash.hash_for_block(&vb, sizeof(F));
    io->send_data(&h, sizeof(block));
    io->flush();
  }
};

// =================================================================
// MpsvoleReceiver — receiver (no Δ) side.
// =================================================================

template <typename Policy, typename IO> class MpsvoleReceiver {
public:
  using F = typename Policy::F;
  using K = typename Policy::K;
  using AuthValue = typename Policy::AuthValue;

  IO *io;
  bool is_malicious = false;
  int64_t tree_n;
  int64_t tree_depth;
  int64_t leave_n;
  std::vector<F> consist_check_chi_alpha;
  std::vector<F> consist_check_VW;
  std::vector<uint32_t> item_pos;    // alpha per tree

  MpsvoleReceiver(int64_t t, int64_t tree_depth_in, IO *io)
      : io(io), tree_n(t), tree_depth(tree_depth_in),
        leave_n(int64_t{1} << tree_depth_in) {}

  void set_malicious() { is_malicious = true; }

  void run_begin() {
    item_pos.assign(tree_n, 0);
    if (is_malicious) {
      consist_check_chi_alpha.assign(tree_n, Policy::f_zero());
      consist_check_VW.assign(tree_n, Policy::f_zero());
    }
  }

  // Per-tree:
  //   1. α = MSB-first concat of NOT(LSB(base_i[j])).
  //   2. recv c[] + secret_sum (one F element).
  //   3. K_recv[j] = c[j] ^ base_i[j].
  //   4. cggm::eval_receiver fills block scratch with hole at α
  //      (zero_block at α).
  //   5. extract → AuthValue (mac in .mac, .val = K{}); nodes_sum =
  //      Σ_{j≠α} leaves[j].mac; leaves[α].mac =
  //      f_sub(triple_yz_i, f_add(secret_sum, nodes_sum)). val at α
  //      inserted by caller after return.
  //   6. (malicious) chi from io->get_digest; chi_alpha[tree_idx]=chi[α];
  //      VW[tree_idx] = Σ chi · leaves.mac.
  // Returns α (= item_pos[tree_idx]).
  uint32_t run_next_tree(AuthValue *leaves_i, const block *base_i,
                         int tree_idx, F triple_yz_i) {
    uint32_t alpha = 0;
    for (int64_t j = 0; j < tree_depth; ++j) {
      alpha <<= 1;
      if (!getLSB(base_i[j])) alpha += 1;
    }
    item_pos[tree_idx] = alpha;

    std::vector<block> c(tree_depth);
    F secret_sum;
    io->recv_block(c.data(), tree_depth);
    io->recv_data(&secret_sum, sizeof(F));

    std::vector<block> K_recv(tree_depth);
    for (int64_t j = 0; j < tree_depth; ++j) K_recv[j] = c[j] ^ base_i[j];

    std::vector<block> leaves_block(leave_n);
    cggm::eval_receiver<cggm::kTile, /*ClearLeafLSB=*/false>(
        tree_depth, alpha, K_recv.data(), leaves_block.data());

    F nodes_sum = Policy::f_zero();
    for (int64_t i = 0; i < leave_n; ++i) {
      if ((uint32_t)i == alpha) {
        leaves_i[i] = AuthValue{};  // placeholder; .mac filled below
        continue;
      }
      leaves_i[i] = Policy::auth_from_block(leaves_block[i]);
      nodes_sum = Policy::f_add(nodes_sum, leaves_i[i].mac);
    }
    leaves_i[alpha].mac =
        Policy::f_sub(triple_yz_i, Policy::f_add(secret_sum, nodes_sum));

    if (is_malicious) {
      block chi_seed = io->get_digest();
      Hash hash;
      block digest_b = hash.hash_for_block(&chi_seed, sizeof(block));
      F digest = Policy::hash_to_f(digest_b);
      std::vector<F> chi(leave_n);
      uni_hash_coeff_gen(chi.data(), digest, leave_n);
      consist_check_chi_alpha[tree_idx] = chi[alpha];
      F v = Policy::f_zero();
      for (int64_t i = 0; i < leave_n; ++i)
        v = Policy::f_add(v, Policy::f_mul(chi[i], leaves_i[i].mac));
      consist_check_VW[tree_idx] = v;
    }

    return alpha;
  }

  // Round-final chi-fold (F2k-style universal convention):
  //   x_star = Σ scalar_mul(triples[i].val, chi_alpha[i]) +
  //            embed(triple_t.val);
  //   send x_star;
  //   va = triple_t.mac + Σ VW;
  //   recv sender's digest; compare hash(va).
  void run_end(const AuthValue *triples, AuthValue triple_t) {
    if (!is_malicious) return;
    F beta_mul_chialpha = Policy::f_zero();
    for (int64_t i = 0; i < tree_n; ++i) {
      F tmp = Policy::scalar_mul(triples[i].val,
                                 consist_check_chi_alpha[i]);
      beta_mul_chialpha = Policy::f_add(beta_mul_chialpha, tmp);
    }
    F x_star =
        Policy::f_add(beta_mul_chialpha, Policy::embed(triple_t.val));
    io->send_data(&x_star, sizeof(F));
    io->flush();

    F va = triple_t.mac;
    for (int64_t i = 0; i < tree_n; ++i)
      va = Policy::f_add(va, consist_check_VW[i]);

    Hash hash;
    block h = hash.hash_for_block(&va, sizeof(F));
    block r;
    io->recv_data(&r, sizeof(block));
    if (!cmpBlock(&r, &h, 1)) error("Mpsvole chi-fold check failed");
  }
};

} // namespace emp
#endif
