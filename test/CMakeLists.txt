# Correctness tests (CI): registered as ctest cases, run via the `run` script
# (two-party loopback). Performance benchmarks live in ../bench (build-only).
function(add_test_case name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE emp-ot::emp-ot)
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    add_test(NAME ${name}
             COMMAND ${name}
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endfunction()

# Two-party tests run under ./run, which takes the port from EMP_PORT. Each gets
# its own port, so `ctest -j` never runs two of them on one port. The ports
# start at 21000, below the range the OS assigns to outgoing connections (32768
# and up on Linux, 49152 and up on macOS), so no outgoing connection can hold a
# test's port. A test that opens more than one port declares how many (PORTS n)
# and owns EMP_PORT .. EMP_PORT + n - 1.
set_property(GLOBAL PROPERTY EMP_OT_TEST_NEXT_PORT 21000)
function(next_test_port out)
    set(count 1)
    if(ARGC GREATER 1)
        set(count ${ARGV1})
    endif()
    get_property(port GLOBAL PROPERTY EMP_OT_TEST_NEXT_PORT)
    math(EXPR next "${port} + ${count}")
    set_property(GLOBAL PROPERTY EMP_OT_TEST_NEXT_PORT ${next})
    set(${out} ${port} PARENT_SCOPE)
endfunction()

function(add_test_case_with_run name)
    cmake_parse_arguments(ARG "" "PORTS" "" ${ARGN})
    if(NOT ARG_PORTS)
        set(ARG_PORTS 1)
    endif()
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE emp-ot::emp-ot)
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    add_test(NAME ${name}
             COMMAND ${PROJECT_SOURCE_DIR}/run $<TARGET_FILE:${name}>
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    # The harness times out at 120 seconds by default; leave enough time for
    # it to terminate and reap both party process groups before CTest intervenes.
    # Unoptimized and instrumented builds get longer: one round of the smallest
    # LPN set is 1.2M outputs, at a small fraction of Release speed.
    next_test_port(port ${ARG_PORTS})
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        set_tests_properties(${name} PROPERTIES TIMEOUT 130
                             ENVIRONMENT "EMP_PORT=${port}")
    else()
        set_tests_properties(${name} PROPERTIES TIMEOUT 310
                             ENVIRONMENT "EMP_PORT=${port};EMP_RUN_TIMEOUT=300")
    endif()
endfunction()

# Shell-level regression coverage for the two-party process supervisor itself.
add_test(NAME test_run
         COMMAND /bin/bash ${PROJECT_SOURCE_DIR}/test/test_run.sh
                           ${PROJECT_SOURCE_DIR}/run
         WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
set_tests_properties(test_run PROPERTIES TIMEOUT 20)

# Per-build-dir tuning_local.h mechanism: stub semantics, override
# visibility, and the include-order shadowing the build relies on.
add_test(NAME test_tuning_local
         COMMAND /bin/bash ${PROJECT_SOURCE_DIR}/test/test_tuning_local.sh
                           ${CMAKE_CXX_COMPILER} ${EMP_OT_TUNING_INCLUDE_DIR}
                           ${EMP_OT_TUNING_STUB_H}
         WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
set_tests_properties(test_tuning_local PROPERTIES TIMEOUT 30)

# Output-invariance of the `make tune` LOCAL knobs (single-process).
add_test_case(test_tuning_invariance)

# LPN fold over GF(2^128) against a per-entry reference (single-process).
add_test_case(test_lpn)

# Release-surviving public/security contract checks (single-process).
add_test_case(test_contracts)
set_tests_properties(test_contracts PROPERTIES TIMEOUT 10)

# Per-primitive correctness drivers (assert via check_*/verify_rcot in test.h).
add_test_case_with_run(test_base_ot)
add_test_case_with_run(test_iknp)
add_test_case_with_run(test_softspoken)
add_test_case_with_run(test_softspoken_lanes PORTS 56)   # base steps by L + 2 per sub-test
add_test_case_with_run(test_ferret)
add_test_case_with_run(test_silentferret)
add_test_case_with_run(test_f2k_vole)
add_test_case_with_run(test_fp_vole)
add_test_case_with_run(test_choice_seed)
add_test_case_with_run(test_extension_check)

# Wire-equivalence / trace harnesses (self-checking via verify_rcot / digest diff).
add_test_case_with_run(trace_equiv)
add_test_case_with_run(trace_hash)

# Wire-format gate: diff trace_hash's digests against the checked-in baseline.
# The digests are deterministic only in a test-mode build — emp-tool configured
# with -DEMP_TEST_MODE=ON, which it exports as a compile definition on its
# target — and the baseline is a Release artifact: trace_hash's NDEBUG-gated
# lengths make Debug digests differ. Any other tree skips the gate.
get_target_property(_emp_tool_defs emp-tool::emp-tool INTERFACE_COMPILE_DEFINITIONS)
if(CMAKE_BUILD_TYPE STREQUAL "Release" AND "EMP_TEST_MODE" IN_LIST _emp_tool_defs)
    add_test(NAME trace_hash_baseline
             COMMAND /bin/bash ${PROJECT_SOURCE_DIR}/test/trace_hash_baseline.sh
                               ${PROJECT_SOURCE_DIR}/run
                               $<TARGET_FILE:trace_hash>
                               ${PROJECT_SOURCE_DIR}/test/trace_hash.baseline
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    next_test_port(port)
    set_tests_properties(trace_hash_baseline PROPERTIES TIMEOUT 130
                         ENVIRONMENT "EMP_PORT=${port}")
endif()
