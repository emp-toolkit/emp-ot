/** @defgroup OT Oblivious Transfer
*/

#include "emp-ot/ot.h"
#include "emp-ot/ideal.h"

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
#include "emp-ot/mextension.h"

#include "emp-ot/deltaot.h"

//typedef MOTExtension_ALSZ MOTExtension;
