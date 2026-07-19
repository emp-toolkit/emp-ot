# `make tune` — per-machine sweep of the LOCAL tuning knobs.
#
# The tuner uses header-only kernels and links no emp-ot objects, so it
# can be built and run BEFORE the library compiles. That is what makes
# the Release auto-tune hook below sound: the sweep runs on an otherwise
# idle machine (nothing else is compiling — every other target waits on
# it), and the library is then compiled WITH the emitted overrides in
# the same build invocation. The override header is per build directory
# (EMP_OT_TUNING_LOCAL_H, created as a stub at configure time — see the
# top-level CMakeLists), so it is in every TU's depfile from the first
# compile and a rewrite here recompiles the affected TUs by itself.
add_executable(emp-ot-tune EXCLUDE_FROM_ALL tune.cpp)
target_link_libraries(emp-ot-tune PRIVATE emp-tool::emp-tool)
target_include_directories(emp-ot-tune PRIVATE
    "${EMP_OT_TUNING_INCLUDE_DIR}"
    "${PROJECT_SOURCE_DIR}")
set_target_properties(emp-ot-tune PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# Explicit re-sweep: always measures and overwrites this build dir's
# tuning_local.h.
add_custom_target(tune
    COMMAND $<TARGET_FILE:emp-ot-tune> --emit "${EMP_OT_TUNING_LOCAL_H}"
    DEPENDS emp-ot-tune
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    COMMENT "Sweeping LOCAL tuning knobs (writes ${EMP_OT_TUNING_LOCAL_H})"
    VERBATIM)

# Back to shipped defaults: copy the canonical, explicitly marked untuned
# stub over the build-dir header. The fresh mtime makes the next build
# recompile consumers without the overrides. Also removes a pre-redesign
# source-tree copy, which CMake builds no longer read.
add_custom_target(tune-clean
    COMMAND ${CMAKE_COMMAND} -E copy
            "${EMP_OT_TUNING_STUB_H}" "${EMP_OT_TUNING_LOCAL_H}"
    COMMAND ${CMAKE_COMMAND} -E rm -f
            "${PROJECT_SOURCE_DIR}/emp-ot/tuning_local.h"
    COMMENT "Restoring the untuned tuning_local.h stub (shipped defaults)"
    VERBATIM)

# Release auto-tune: top-level Release builds sweep ONCE per build
# directory — while the file holds a tuned result the run is a fast
# no-op, so builds stay deterministic after the first one (the stub from
# configure or tune-clean does not count as tuned). Debug builds,
# subproject consumers (tools/ is only added top-level), cross builds,
# and -DEMP_OT_AUTO_TUNE=OFF never auto-run; `tune`/`tune-clean` stay
# available for explicit control either way.
if(EMP_OT_AUTO_TUNE_ACTIVE)
    add_custom_target(tune-auto ALL
        COMMAND $<TARGET_FILE:emp-ot-tune> --emit-if-untuned
                "${EMP_OT_TUNING_LOCAL_H}"
        DEPENDS emp-ot-tune
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
        COMMENT "auto-tune: one-time LOCAL-knob sweep for this build directory (Release)"
        VERBATIM)
    # Sequence the whole build behind the sweep: the library (and hence
    # every bench/test) compiles only after the overrides exist.
    add_dependencies(emp-ot tune-auto)
endif()
