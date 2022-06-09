#ifndef EMP_FERRET_CONSTANTS_H__
#define EMP_FERRET_CONSTANTS_H__

namespace emp { 
static std::string PRE_OT_DATA_REG_SEND_FILE = "./data/pre_ot_data_reg_send";
static std::string PRE_OT_DATA_REG_RECV_FILE = "./data/pre_ot_data_reg_recv";

// Parameters chosen based on https://eprint.iacr.org/2022/712
const static int64_t N_REG = 10485760;
const static int64_t T_REG = 1280;
const static int64_t K_REG = 452000;
const static int64_t BIN_SZ_REG = 13;
const static int64_t N_PRE_REG = 470016;
const static int64_t T_PRE_REG = 918;
const static int64_t K_PRE_REG = 32768;
const static int64_t BIN_SZ_PRE_REG = 9;
}//namespace
#endif //EMP_FERRET_CONSTANTS_H__
