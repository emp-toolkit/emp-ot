/** @defgroup OT Oblivious Transfer
*/

#include "emp-ot/ot.h"
#include "emp-ot/ideal.h"

#include "emp-ot/co.h"
#include "emp-ot/np.h"

#include "emp-ot/shextension.h"
#include "emp-ot/ot_extension.h"
#include "emp-ot/mextension_kos.h"
#include "emp-ot/mextension_alsz.h"

template<typename IO>
using MOTExtension = emp::MOTExtension_KOS<IO>;
//typedef MOTExtension_ALSZ MOTExtension;
