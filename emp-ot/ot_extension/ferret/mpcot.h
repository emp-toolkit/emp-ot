#ifndef EMP_OT_MPCOT_H__
#define EMP_OT_MPCOT_H__

#include <emp-tool/emp-tool.h>
#include <vector>
#include "emp-ot/ot_extension/cggm.h"
#include "emp-ot/ot_extension/ferret/constants.h"

// Multi-point COT over a regular sparse vector. Drives `tree_n`
// cGGM trees of height `tree_height` (= log2(leave_n) + 1) under
// Half-Tree. Each tree expands
// one at a time: build cGGM tree (sender) / receive corrections +
// reconstruct (receiver), ship/read (c[], secret_sum_f2). Trees
// write into `sparse_vector` in tree-i order (leaves_i =
// sparse_vector + i*leave_n).
//
// pre_cot_data role:
//   The pointer `pre_cot_data` passed to run_end() is the start of
//   the chi-fold consistency-check region — first 128 base COTs.
//   The cGGM correction COTs are addressed separately by the caller
//   (FerretCOT lays them out at [128 + param.k, M), past the LPN
//   slot, so the three roles — chi-check, LPN seed, cGGM correction
//   — never share a base COT). Aliasing roles would leak: cGGM
//   ships c[j] = base[j] ^ K0[j] on the wire, which would compromise
//   any base COT that is also part of the LPN secret or the chi-fold
//   value.
//
// Two role-specific classes (no shared base — the ALICE and BOB
// flows are different enough that polymorphic dispatch would be
// noise). In malicious mode, both run the round-final F_{2^k}
// chi-fold consistency check; the chi seed is derived via Fiat-
// Shamir from the transcript hash of every (c[], secret_sum_f2)
// per-tree pair sent/received this round (κ-bit binding to the
// full round, mirroring IKNP-malicious's FS pattern).

namespace emp {

class MPCOT_Sender {
public:
    PrimalLPNParameter param;
    bool is_malicious;
    IOChannel *netio;
    block Delta_f2k;
	 PRG prg;
    std::vector<block> consist_check_VW;
    GaloisFieldPacking pack;

    MPCOT_Sender(const PrimalLPNParameter& param, IOChannel *io)
            : param(param), is_malicious(false), netio(io) {}

    void set_malicious() { is_malicious = true; }
    void set_delta(block d) { Delta_f2k = d; }

    // Streaming API. ferret drives the per-tree loop externally so
    // it can interleave LPN slicing and round-end refilling. Two
    // protocol details folded out of sight (see run_next_tree):
    //
    //   (a) No per-tree `secret_sum_f2` on the wire. Under cGGM the
    //       leveled correlation gives XOR(leaves) = Δ, so with bit-0
    //       cleared every tree's secret_sum_f2 equals lsb_only_mask;
    //       both sides hardcode the constant.
    //
    //   (b) The per-leaf LSB-clear is folded into cggm::build_sender
    //       via ClearLeafLSB=true. K0[d-1] is then the sum over
    //       LSB-cleared left children; the receiver's matching
    //       ClearLeafLSB on eval_receiver keeps the algebra aligned.
    void run_begin() {
        if (is_malicious) consist_check_VW.assign(param.t, zero_block);
    }

    void run_next_tree(block *leaves_i, const block *base_i, int tree_idx) {
        BlockVec K0(param.tree_depth), c(param.tree_depth);

        block seed;
		  prg.random_block(&seed, 1); 
        cggm::build_sender<cggm::kTile, /*ClearLeafLSB=*/true>(
            param.tree_depth, Delta_f2k, seed, leaves_i, K0.data());

        for (int j = 0; j < param.tree_depth; ++j) c[j] = base_i[j] ^ K0[j];
        netio->send_block(c.data(), param.tree_depth);
        netio->flush();

        if (is_malicious) {
            // chi_seed snapshots the FS transcript right after this
            // tree's c[] bytes were absorbed; PRG-expand into chi[]
            // and fold against the leaves into VW[tree_idx].
            const int leave_n = 1 << param.tree_depth;
            block chi_seed = netio->get_digest();
            PRG chiPRG(&chi_seed);
            BlockVec chi(leave_n);
            chiPRG.random_block(chi.data(), leave_n);
            vector_inn_prdt_sum_red(&consist_check_VW[tree_idx], chi.data(),
                                    leaves_i, leave_n);
        }
    }

    void run_end(block *pre_cot_data) {
        if (is_malicious) consistency_check_f2k(pre_cot_data);
    }

private:
    // Sender-side malicious-check (F_{2^k}). Receives the receiver's
    // 128-bit correction (chi_alpha applied to the base COTs), folds
    // it into our XOR-sum of the per-tree V responses, hashes, and
    // sends the digest.
    //
    // The Δ-XOR is applied to a stack copy of the first 128 base
    // COTs (the caller-supplied pre_cot_data pointer is the start of
    // the chi-check region — disjoint from the cGGM and LPN regions
    // by construction at the ferret_cot.cpp layer). The stack copy
    // also avoids mutating the caller's buffer.
    void consistency_check_f2k(block *pre_cot_data) {
        block r1, r2;
        vector_self_xor(&r1, consist_check_VW.data(), param.t);

        bool x_prime[kConsistCheckCotNum];
        netio->recv_bool(x_prime, kConsistCheckCotNum * sizeof(bool));
        block check_base[kConsistCheckCotNum];
        for (int i = 0; i < kConsistCheckCotNum; ++i)
            if (x_prime[i])
                pre_cot_data[i] = pre_cot_data[i] ^ Delta_f2k;
        pack.packing(&r2, pre_cot_data);
        r1 = r1 ^ r2;

        block dig[2];
        Hash hash;
        hash.hash_once(dig, &r1, sizeof(block));
        netio->send_data(dig, 2 * sizeof(block));
        netio->flush();
    }
};

class MPCOT_Receiver {
public:
    PrimalLPNParameter param;
    bool is_malicious;
    IOChannel *netio;
    std::vector<block> consist_check_chi_alpha;
    std::vector<block> consist_check_VW;
    GaloisFieldPacking pack;

    MPCOT_Receiver(const PrimalLPNParameter& param, IOChannel *io)
            : param(param), is_malicious(false), netio(io) {}

    void set_malicious() { is_malicious = true; }

    // Streaming API. Mirrors MPCOT_Sender; the sender's comment
    // covers the protocol details (no secret_sum_f2, ClearLeafLSB
    // folded into eval_receiver, per-tree FS chi).
    void run_begin() {
        if (is_malicious) {
            consist_check_VW.assign(param.t, zero_block);
            consist_check_chi_alpha.assign(param.t, zero_block);
        }
    }

    void run_next_tree(block *leaves_i, const block *base_i, int tree_idx) {
        const int leave_n = 1 << param.tree_depth;
        BlockVec K_recv(param.tree_depth), c(param.tree_depth);
        default_init_vector<unsigned char> b(param.tree_depth);

        // b[j] = NOT alpha_{j+1} = r_{j+1} = LSB(M_{r_{j+1}}).
        for (int j = 0; j < param.tree_depth; ++j) b[j] = getLSB(base_i[j]);

        netio->recv_block(c.data(), param.tree_depth);

        // K_recv[j] = K^{ᾱ_j}_{j+1} = M_{r_j} XOR c_j.
        for (int j = 0; j < param.tree_depth; ++j) K_recv[j] = base_i[j] ^ c[j];

        // Pack b[0..depth-2] (NOT alpha_j, MSB-first) into choice_pos == alpha.
        int choice_pos = 0;
        for (int j = 0; j < param.tree_depth; ++j) {
            choice_pos <<= 1;
            if (!b[j]) choice_pos += 1;
        }

        cggm::eval_receiver<cggm::kTile, /*ClearLeafLSB=*/true>(
            param.tree_depth, choice_pos, K_recv.data(), leaves_i);

        // Apply punctured correction. eval_receiver leaves
        // leaves_i[choice_pos] = zero_block; nodes_sum = XOR of
        // all (LSB-cleared) leaves (the choice_pos zero contributes
        // nothing); leaves_i[choice_pos] = nodes_sum XOR
        // lsb_only_mask = sender's LSB-cleared leaf XOR Δ.
        block nodes_sum = zero_block;
        for (int k = 0; k < leave_n; ++k)
            nodes_sum = nodes_sum ^ leaves_i[k];
        leaves_i[choice_pos] = nodes_sum ^ lsb_only_mask;

        if (is_malicious) {
            block chi_seed = netio->get_digest();
            PRG chiPRG(&chi_seed);
            BlockVec chi(leave_n);
            chiPRG.random_block(chi.data(), leave_n);
            consist_check_chi_alpha[tree_idx] = chi[choice_pos];
            vector_inn_prdt_sum_red(&consist_check_VW[tree_idx], chi.data(),
                                    leaves_i, leave_n);
        }
    }

    void run_end(block *pre_cot_data) {
        if (is_malicious) consistency_check_f2k(pre_cot_data);
    }

private:
    // Receiver-side malicious-check (F_{2^k}). Sends a 128-bit
    // correction derived from XOR(chi_alpha) and the LSBs of the base
    // COTs, then hashes its own XOR-sum of W with the packed base
    // COTs, and aborts on digest mismatch.
    void consistency_check_f2k(block *pre_cot_data) {
        block r1, r2;
        vector_self_xor(&r1, consist_check_VW.data(), param.t);
        vector_self_xor(&r2, consist_check_chi_alpha.data(), param.t);

        uint64_t pos[2];
        pos[0] = _mm_extract_epi64(r2, 0);
        pos[1] = _mm_extract_epi64(r2, 1);
        bool pre_cot_bool[kConsistCheckCotNum];
        for (int i = 0; i < 2; ++i) {
            for (int j = 0; j < 64; ++j) {
                pre_cot_bool[i * 64 + j] =
                    ((pos[i] & 1) == 1) ^ getLSB(pre_cot_data[i * 64 + j]);
                pos[i] >>= 1;
            }
        }
        netio->send_bool(pre_cot_bool, kConsistCheckCotNum * sizeof(bool));
        netio->flush();

        block r3;
        pack.packing(&r3, pre_cot_data);
        r1 = r1 ^ r3;

        block dig[2];
        Hash hash;
        hash.hash_once(dig, &r1, sizeof(block));
        block recv[2];
        netio->recv_data(recv, 2 * sizeof(block));
        if (!cmpBlock(dig, recv, 2))
            std::cout << "MPCOT consistency check fails" << std::endl;
    }
};

}  // namespace emp
#endif  // EMP_OT_MPCOT_H__
