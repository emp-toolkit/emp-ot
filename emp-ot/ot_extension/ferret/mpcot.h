#ifndef EMP_OT_MPCOT_H__
#define EMP_OT_MPCOT_H__

#include <emp-tool/emp-tool.h>
#include <vector>
#include "emp-ot/ot_extension/cggm.h"
#include "emp-ot/ot_extension/ferret/constants.h"

// Multi-point COT over a regular sparse vector. Drives `tree_n`
// cGGM trees of height `tree_height` (= log2(leave_n) + 1) under
// Half-Tree (Roy '22, ePrint 2022/1431, Fig 4). Each tree expands
// one at a time: build cGGM tree (sender) / receive corrections +
// reconstruct (receiver), ship/read (c[], secret_sum_f2). Trees
// write into `sparse_vector` in tree-i order (leaves_i =
// sparse_vector + i*leave_n).
//
// pre_cot_data layout (passed in by caller):
//   [0 .. tree_n*(h-1)) : per-tree base COTs feeding the cGGM
//                         level corrections. ALICE has K_{r_i};
//                         BOB has M_{r_i} = K_{r_i} XOR r_i*Delta.
//   [0 .. 128)          : ALSO consumed by the malicious-mode
//                         consistency check (aliasing — both reads
//                         are non-destructive and the security
//                         argument covers both uses).
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
    static constexpr int kConsistCheckCotNum = 128;

    int item_n, idx_max;
    int tree_height, leave_n;
    int tree_n;
    bool is_malicious;
    IOChannel *netio;
    block Delta_f2k;
    std::vector<block> consist_check_VW;
    GaloisFieldPacking pack;

    MPCOT_Sender(int n, int t, int log_bin_sz, IOChannel *io)
            : item_n(t), idx_max(n),
              tree_height(log_bin_sz + 1), leave_n(1 << log_bin_sz),
              tree_n(t),
              is_malicious(false),
              netio(io) {}

    void set_malicious() { is_malicious = true; }
    void set_delta(block d) { Delta_f2k = d; }

    void run(block *sparse_vector, block *pre_cot_data) {
        const int n_lvl = tree_height - 1;
        BlockVec K0(n_lvl), c(n_lvl);
        if (is_malicious) consist_check_VW.assign(item_n, zero_block);

        // Pass 1: per-tree cGGM build, ship corrections.
        //
        // Two protocol details folded out of sight here:
        //
        // (1) No per-tree `secret_sum_f2` on the wire. Under cGGM the
        //     leveled correlation gives XOR(leaves) = Δ, and Δ has
        //     bit 0 = 1 by construction. Clearing bit 0 of every leaf
        //     turns the leaf XOR into Δ XOR lsb_only_mask, so
        //         secret_sum_f2 = Δ XOR XOR(LSB-cleared leaves)
        //                       = lsb_only_mask
        //     for *every* tree of *every* round. Both sides hardcode
        //     the constant; nothing about it needs transmitting.
        //
        // (2) The per-leaf LSB-clear is folded into cggm::build_sender
        //     via ClearLeafLSB=true. K0[d-1] is then the sum over
        //     LSB-cleared left children; the receiver uses the matching
        //     ClearLeafLSB on eval_receiver and the algebra lines up.
        //     Saves a separate AND-pass over 2^d-leaf arrays.
        //
        // The chi_seed for the malicious consistency check (Pass 2) is
        // pulled from netio->get_digest(): IOChannel's FS transcript
        // automatically absorbed every byte of c[] as it went on the
        // wire (FS was enabled in FerretCOT::setup for malicious mode).
        // Both parties' transcripts agree byte-for-byte.
        for (int i = 0; i < tree_n; ++i) {
            block *leaves_i = sparse_vector + i * leave_n;
            const block *base_i = pre_cot_data + i * n_lvl;

            block seed;
            { PRG prg; prg.random_block(&seed, 1); }
            cggm::build_sender<cggm::kTile, /*ClearLeafLSB=*/true>(
                n_lvl, Delta_f2k, seed, leaves_i, K0.data());

            // c_j = K_{r_j} XOR K^0_j.
            for (int j = 0; j < n_lvl; ++j) c[j] = base_i[j] ^ K0[j];
            netio->send_block(c.data(), n_lvl);
            netio->flush();
        }

        if (!is_malicious) return;

        // Pass 2: per-tree chi from FS digest, fold against leaves.
        const block chi_seed = netio->get_digest();
        BlockVec chi(leave_n);
        for (int i = 0; i < tree_n; ++i) {
            block tree_inp[2] = { chi_seed, makeBlock(0, i) };
            block tree_dig[2];
            Hash::hash_once(tree_dig, tree_inp, sizeof(tree_inp));
            uni_hash_coeff_gen(chi.data(), tree_dig[0], leave_n);
            vector_inn_prdt_sum_red(&consist_check_VW[i], chi.data(),
                                    sparse_vector + i * leave_n, leave_n);
        }

        consistency_check_f2k(pre_cot_data);
    }

private:
    // Sender-side malicious-check (F_{2^k}). Receives the receiver's
    // 128-bit correction (chi_alpha applied to the base COTs), folds
    // it into our XOR-sum of the per-tree V responses, hashes, and
    // sends the digest.
    void consistency_check_f2k(block *pre_cot_data) {
        block r1, r2;
        vector_self_xor(&r1, consist_check_VW.data(), tree_n);

        bool x_prime[kConsistCheckCotNum];
        netio->recv_data(x_prime, kConsistCheckCotNum * sizeof(bool));
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
    static constexpr int kConsistCheckCotNum = 128;

    int item_n, idx_max;
    int tree_height, leave_n;
    int tree_n;
    bool is_malicious;
    IOChannel *netio;
    std::vector<block> consist_check_chi_alpha;
    std::vector<block> consist_check_VW;
    GaloisFieldPacking pack;

    MPCOT_Receiver(int n, int t, int log_bin_sz, IOChannel *io)
            : item_n(t), idx_max(n),
              tree_height(log_bin_sz + 1), leave_n(1 << log_bin_sz),
              tree_n(t),
              is_malicious(false),
              netio(io) {}

    void set_malicious() { is_malicious = true; }

    void run(block *sparse_vector, block *pre_cot_data) {
        const int n_lvl = tree_height - 1;
        BlockVec K_recv(n_lvl), c(n_lvl);
        default_init_vector<unsigned char> b(n_lvl);
        std::vector<int> choice_pos_arr;
        if (is_malicious) {
            consist_check_VW.assign(item_n, zero_block);
            consist_check_chi_alpha.assign(item_n, zero_block);
            choice_pos_arr.assign(item_n, 0);
        }

        // Pass 1: per-tree recv corrections + reconstruct cGGM tree.
        // Same two folded-in details as the sender (no secret_sum_f2
        // on the wire, ClearLeafLSB folded into eval_receiver).
        // chi_seed for Pass 2 comes from netio->get_digest() — IOChannel
        // absorbed every recv'd c[] into the FS transcript automatically.
        for (int i = 0; i < tree_n; ++i) {
            block *leaves_i = sparse_vector + i * leave_n;
            const block *base_i = pre_cot_data + i * n_lvl;

            // b[j] = NOT alpha_{j+1} = r_{j+1} = LSB(M_{r_{j+1}}).
            for (int j = 0; j < n_lvl; ++j) b[j] = getLSB(base_i[j]);

            netio->recv_block(c.data(), n_lvl);

            // K_recv[j] = K^{ᾱ_j}_{j+1} = M_{r_j} XOR c_j.
            for (int j = 0; j < n_lvl; ++j) K_recv[j] = base_i[j] ^ c[j];

            // Pack b[0..depth-2] (NOT alpha_j, MSB-first) into choice_pos == alpha.
            int choice_pos = 0;
            for (int j = 0; j < n_lvl; ++j) {
                choice_pos <<= 1;
                if (!b[j]) choice_pos += 1;
            }
            if (is_malicious) choice_pos_arr[i] = choice_pos;

            cggm::eval_receiver<cggm::kTile, /*ClearLeafLSB=*/true>(
                n_lvl, choice_pos, K_recv.data(), leaves_i);

            // eval_receiver left every level-d leaf with bit 0 clear,
            // including the zero placeholder at choice_pos. nodes_sum =
            // XOR of all leaves (the choice_pos zero contributes
            // nothing); leaves[choice_pos] = nodes_sum XOR lsb_only_mask
            // then equals the sender's LSB-cleared leaf XOR Δ (bit 0 = 1
            // marking the punctured position).
            block nodes_sum = zero_block;
            for (int k = 0; k < leave_n; ++k)
                nodes_sum = nodes_sum ^ leaves_i[k];
            leaves_i[choice_pos] = nodes_sum ^ lsb_only_mask;
        }

        if (!is_malicious) return;

        // Pass 2: per-tree chi from FS digest.
        const block chi_seed = netio->get_digest();
        BlockVec chi(leave_n);
        for (int i = 0; i < tree_n; ++i) {
            block tree_inp[2] = { chi_seed, makeBlock(0, i) };
            block tree_dig[2];
            Hash::hash_once(tree_dig, tree_inp, sizeof(tree_inp));
            uni_hash_coeff_gen(chi.data(), tree_dig[0], leave_n);
            consist_check_chi_alpha[i] = chi[choice_pos_arr[i]];
            vector_inn_prdt_sum_red(&consist_check_VW[i], chi.data(),
                                    sparse_vector + i * leave_n, leave_n);
        }

        consistency_check_f2k(pre_cot_data);
    }

private:
    // Receiver-side malicious-check (F_{2^k}). Sends a 128-bit
    // correction derived from XOR(chi_alpha) and the LSBs of the base
    // COTs, then hashes its own XOR-sum of W with the packed base
    // COTs, and aborts on digest mismatch.
    void consistency_check_f2k(block *pre_cot_data) {
        block r1, r2;
        vector_self_xor(&r1, consist_check_VW.data(), tree_n);
        vector_self_xor(&r2, consist_check_chi_alpha.data(), tree_n);

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
        netio->send_data(pre_cot_bool, kConsistCheckCotNum * sizeof(bool));
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
