#ifndef EMP_OT_SVOLE_EXTENSION_H__
#define EMP_OT_SVOLE_EXTENSION_H__

#include "emp-ot/common/streaming_extension.h"

// sVOLE extensions are just StreamingExtension<AuthValue>. The
// concrete carrier type (AuthValueF2k / AuthValueFp) provides both
// the storage layout and the F-arithmetic + chi-fold + LPN ops;
// nothing sVOLE-specific lives at this layer.

namespace emp {

template <typename AuthValue>
using SVoleExtension = StreamingExtension<AuthValue>;

}  // namespace emp
#endif
