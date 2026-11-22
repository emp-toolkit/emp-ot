/* ML-KEM-512 for the BMM base OT, plus mlkem-native's level-independent
 * code, which the other levels share (see mlkem_level.h, mlkem_config.h). */
#define MLK_CONFIG_PARAMETER_SET 512
#define MLK_CONFIG_MULTILEVEL_WITH_SHARED
#include "emp-ot/base_ot/mlkem/mlkem_level.h"
