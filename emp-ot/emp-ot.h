/** @defgroup OT Oblivious Transfer
*/

#include "emp-ot/ot.h"
#include "emp-ot/ideal.h"
#include "emp-ot/table.h"

// Defines or does not define INCLUDE_LATTICE_OT
// depending on whether or not lattice_ot is available
#include "emp-ot/latticeInclude.h"

// The include is kept here instead of being placed
// in latticeInclude.h so it remains in the documentation
#ifdef INCLUDE_LATTICE_OT
#include "emp-ot/lattice.h"
#endif

#include "emp-ot/co.h"
#include "emp-ot/np.h"

#include "emp-ot/shextension.h"
#include "emp-ot/ot_extension.h"
#include "emp-ot/mextension_kos.h"
#include "emp-ot/mextension_alsz.h"

#include "emp-ot/deltaot.h"

template<typename IO>
using MOTExtension = emp::MOTExtension_KOS<IO>;
//typedef MOTExtension_ALSZ MOTExtension;
