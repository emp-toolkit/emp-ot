# `make tune` — per-machine sweep of the LOCAL tuning knobs.
#
# The tuner uses header-only kernels and links no emp-ot objects, so it
# can be built and run BEFORE the library compiles. That is what makes
# the Release auto-tune hook below sound: the sweep runs on an otherwise
# idle machine (nothing else is compiling — every other target waits on
# it), and the library is then compiled WITH the emitted overrides in
# the same build invocation. The tuner itself touches emp-ot/tuning.h
# whenever it (re)writes tuning_local.h, which is what makes a plain
# rebuild apply the overrides (the __has_include dependency is invisible
# to compiler depfiles until the file exists).
add_executable(emp-ot-tune EXCLUDE_FROM_ALL tune.cpp)
target_link_libraries(emp-ot-tune PRIVATE emp-tool::emp-tool)
target_include_directories(emp-ot-tune PRIVATE "${PROJECT_SOURCE_DIR}")
set_target_properties(emp-ot-tune PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# Explicit re-sweep: always measures and overwrites tuning_local.h.
add_custom_target(tune
    COMMAND $<TARGET_FILE:emp-ot-tune> --emit
            "${PROJECT_SOURCE_DIR}/emp-ot/tuning_local.h"
    DEPENDS emp-ot-tune
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    COMMENT "Sweeping LOCAL tuning knobs (writes emp-ot/tuning_local.h)"
    VERBATIM)

# Back to shipped defaults. The touch forces the next build to recompile
# the consumers without the overrides.
add_custom_target(tune-clean
    COMMAND ${CMAKE_COMMAND} -E rm -f
            "${PROJECT_SOURCE_DIR}/emp-ot/tuning_local.h"
    COMMAND ${CMAKE_COMMAND} -E touch
            "${PROJECT_SOURCE_DIR}/emp-ot/tuning.h"
    COMMENT "Removing emp-ot/tuning_local.h (back to shipped defaults)"
    VERBATIM)

# Release auto-tune: top-level Release builds sweep ONCE per machine —
# if tuning_local.h already exists (even with zero overrides) the run is
# a fast no-op, so builds stay deterministic after the first one. Debug
# builds, subproject consumers (tools/ is only added top-level), cross
# builds, and -DEMP_OT_AUTO_TUNE=OFF never auto-run; `tune`/`tune-clean`
# stay available for explicit control either way.
if(EMP_OT_AUTO_TUNE)
    add_custom_target(tune-auto ALL
        COMMAND $<TARGET_FILE:emp-ot-tune> --emit-if-absent
                "${PROJECT_SOURCE_DIR}/emp-ot/tuning_local.h"
        DEPENDS emp-ot-tune
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
        COMMENT "auto-tune: one-time LOCAL-knob sweep for this machine (Release)"
        VERBATIM)
    # Sequence the whole build behind the sweep: the library (and hence
    # every bench/test) compiles only after the overrides exist.
    add_dependencies(emp-ot tune-auto)
endif()
