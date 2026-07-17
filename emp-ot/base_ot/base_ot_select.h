#ifndef EMP_OT_BASE_OT_SELECT_H__
#define EMP_OT_BASE_OT_SELECT_H__

// Runtime base-OT selection. The OT-extension backends (SoftSpoken) already take
// a polymorphic `std::unique_ptr<OT>` base OT; this enum + factory let a consumer
// pick one at run time (per instance) instead of editing the compile-time
// SoftSpokenBaseOT alias. The extension's own runtime guard
// (OTExtension: malicious_ && !base_ot->is_malicious_secure()) still applies.

#include <memory>
#include "emp-ot/ot.h"
#include "emp-ot/base_ot/co.h"
#include "emp-ot/base_ot/pvw.h"
#include "emp-ot/base_ot/csw.h"
#include "emp-ot/base_ot/bmm.h"

namespace emp {

// CSW = CDH/EC "Blazing Fast" OT; BMM = lattice (ML-KEM-512 / Kyber, 2022/415);
// CO = Chou-Orlandi (semi-honest); PVW = Peikert-Vaikuntanathan-Waters.
enum class BaseOtKind { CSW, BMM, CO, PVW };

inline std::unique_ptr<OT> make_base_ot(BaseOtKind kind, IOChannel* io) {
  switch (kind) {
    case BaseOtKind::CSW: return std::make_unique<CSW>(io);
    case BaseOtKind::BMM: return std::make_unique<BMM>(io);
    case BaseOtKind::CO:  return std::make_unique<CO>(io);
    case BaseOtKind::PVW: return std::make_unique<PVW>(io);
  }
  expecting(false, "make_base_ot: invalid BaseOtKind");
  return nullptr;
}

}  // namespace emp

#endif  // EMP_OT_BASE_OT_SELECT_H__
