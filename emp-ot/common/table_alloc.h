#ifndef EMP_OT_TABLE_ALLOC_H__
#define EMP_OT_TABLE_ALLOC_H__

#include "emp-tool/runtime/core/block_vector.h"   // default_init_allocator
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <vector>
#if defined(__linux__)
#include <sys/mman.h>
#endif

namespace emp {

// Allocator for the round carry buffers of Ferret, SilentFerret and the two
// sVOLEs. Part of the active buffer is the LPN table (Ferret: slots
// [128, 128 + k); sVOLE: [t + 1, t + 1 + k)), and every output gathers d
// random entries from it, so the table's placement in cache lines and pages
// matters.
//
// Lines. Every buffer starts on a 64-byte line. An AuthValueF2k entry is
// 32 bytes and the table starts on an entry boundary, so each entry then lies
// inside one line. The default allocator promises only 16 bytes: from a base
// at 16 mod 32, every other entry spans two lines and its gather reads both.
// Only the buffer is over-aligned; the carrier types keep their own
// alignment, which callers' layouts depend on.
//
// Pages (Linux). With 4 KiB pages a multi-MiB table spans thousands of
// pages, so nearly every gather also misses the TLB. A buffer of at least one
// 2 MiB huge page is therefore mapped on its own 2 MiB-aligned range, rounded
// up to whole huge pages, and advised MADV_HUGEPAGE, so transparent huge
// pages back it when the system's THP mode is `madvise` or `always`. The
// advice changes how the memory is mapped, never its contents; where THP is
// off the range keeps 4 KiB pages.
template <typename T>
struct LpnTableAllocator {
  using value_type = T;
  static constexpr std::size_t kLine = 64;
  static constexpr std::size_t kHugePage = std::size_t{1} << 21;

  LpnTableAllocator() noexcept = default;
  template <typename U>
  LpnTableAllocator(const LpnTableAllocator<U> &) noexcept {}

  T *allocate(std::size_t n) {
    if (n > std::numeric_limits<std::size_t>::max() / sizeof(T))
      throw std::bad_array_new_length();
#if defined(__linux__)
    if (n * sizeof(T) >= kHugePage)
      return static_cast<T *>(map_huge_(n * sizeof(T)));
#endif
    return static_cast<T *>(
        ::operator new(n * sizeof(T), std::align_val_t{kLine}));
  }
  void deallocate(T *p, std::size_t n) noexcept {
#if defined(__linux__)
    if (n * sizeof(T) >= kHugePage) {
      munmap(p, round_up_(n * sizeof(T)));
      return;
    }
#endif
    (void)n;
    ::operator delete(p, std::align_val_t{kLine});
  }

  template <typename U>
  bool operator==(const LpnTableAllocator<U> &) const noexcept {
    return true;
  }

private:
#if defined(__linux__)
  static std::size_t round_up_(std::size_t bytes) {
    return (bytes + kHugePage - 1) & ~(kHugePage - 1);
  }
  // Map one huge page more than needed, keep the 2 MiB-aligned window and
  // unmap the rest.
  static void *map_huge_(std::size_t bytes) {
    if (bytes > std::numeric_limits<std::size_t>::max() - 2 * kHugePage)
      throw std::bad_alloc();
    const std::size_t len = round_up_(bytes);
    const std::size_t span = len + kHugePage;
    void *raw = mmap(nullptr, span, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED) throw std::bad_alloc();
    const std::uintptr_t lo = reinterpret_cast<std::uintptr_t>(raw);
    const std::uintptr_t start =
        (lo + kHugePage - 1) & ~std::uintptr_t{kHugePage - 1};
    if (start != lo) munmap(raw, start - lo);
    const std::size_t tail = (lo + span) - (start + len);
    if (tail != 0) munmap(reinterpret_cast<void *>(start + len), tail);
    void *p = reinterpret_cast<void *>(start);
    // Advisory only: if it fails, the range keeps 4 KiB pages.
    (void)madvise(p, len, MADV_HUGEPAGE);
    return p;
  }
#endif
};

// Ferret's carry buffers hold raw blocks and, like BlockVec, skip the
// zero-fill on resize.
using LpnTableBlockVec =
    std::vector<block, default_init_allocator<block, LpnTableAllocator<block>>>;

}  // namespace emp
#endif
