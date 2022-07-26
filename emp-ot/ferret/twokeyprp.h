#ifndef EMP_FERRET_TWO_KEY_PRP_H__
#define EMP_FERRET_TWO_KEY_PRP_H__

#include "emp-tool/emp-tool.h"
using namespace emp;

//kappa->2kappa PRG, implemented as G(k) = PRF_seed0(k)\xor k || PRF_seed1(k)\xor k
class TwoKeyPRP { public:
	emp::AES_KEY aes_key[2];

	TwoKeyPRP(block seed0, block seed1) {
		AES_set_encrypt_key((const block)seed0, aes_key);
		AES_set_encrypt_key((const block)seed1, &aes_key[1]);
	}

	void node_expand_1to2(block *children, block parent) {
		block tmp[2];
		tmp[0] = children[0] = parent;
		tmp[1] = children[1] = parent;
		ParaEnc<2,1>(tmp, aes_key);
		children[0] = children[0] ^ tmp[0];
		children[1] = children[1] ^ tmp[1];
	}

	void node_expand_2to4(block *children, block *parent) {
		//p[0],           p[1]
		//c[0], c[1]      c[2], c[3]
		//t[0]  t[2]      t[1]  t[3]
		block tmp[4];
		tmp[3] = children[3] = parent[1];
		tmp[1] = children[2] = parent[1];
		tmp[2] = children[1] = parent[0];
		tmp[0] = children[0] = parent[0];
		ParaEnc<2,2>(tmp, aes_key);
		children[3] = children[3] ^ tmp[3];
		children[2] = children[2] ^ tmp[1];
		children[1] = children[1] ^ tmp[2];
		children[0] = children[0] ^ tmp[0];
	}
	void node_expand_4to8(block *children, block *parent) {
		//p[0],           p[1]                    p2             p3
		//c[0], c[1]      c[2], c[3],       4      5           6     7
		//t[0]  t[4]      t[1]  t[5]       2       6           3     7
		block tmp[8];
		tmp[7] = children[7] = parent[3];
		tmp[3] = children[6] = parent[3];
		tmp[6] = children[5] = parent[2];
		tmp[2] = children[4] = parent[2];
		tmp[5] = children[3] = parent[1];
		tmp[1] = children[2] = parent[1];
		tmp[4] = children[1] = parent[0];
		tmp[0] = children[0] = parent[0];

		ParaEnc<2,4>(tmp, aes_key);
		children[7] = children[7] ^ tmp[7];
		children[6] = children[6] ^ tmp[3];
		children[5] = children[5] ^ tmp[6];
		children[4] = children[4] ^ tmp[2];
		children[3] = children[3] ^ tmp[5];
		children[2] = children[2] ^ tmp[1];
		children[1] = children[1] ^ tmp[4];
		children[0] = children[0] ^ tmp[0];
	}

};
#endif
