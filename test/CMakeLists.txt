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

function(add_test_case_with_run name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE emp-ot::emp-ot)
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    add_test(NAME ${name}
             COMMAND ${PROJECT_SOURCE_DIR}/run $<TARGET_FILE:${name}>
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    # The harness times out at 120 seconds by default; leave enough time for
    # it to terminate and reap both party process groups before CTest intervenes.
    set_tests_properties(${name} PROPERTIES TIMEOUT 130)
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

# Release-surviving public/security contract checks (single-process).
add_test_case(test_contracts)
set_tests_properties(test_contracts PROPERTIES TIMEOUT 10)

# Per-primitive correctness drivers (assert via check_*/verify_rcot in test.h).
add_test_case_with_run(test_base_ot)
add_test_case_with_run(test_iknp)
add_test_case_with_run(test_softspoken)
add_test_case_with_run(test_softspoken_lanes)
add_test_case_with_run(test_ferret)
add_test_case_with_run(test_silentferret)
add_test_case_with_run(test_f2k_vole)
add_test_case_with_run(test_fp_vole)
add_test_case_with_run(test_choice_seed)

# Wire-equivalence / trace harnesses (self-checking via verify_rcot / digest diff).
add_test_case_with_run(trace_equiv)
add_test_case_with_run(trace_hash)

# Wire-format gate: diff trace_hash's deterministic (EMP_TEST_MODE) digests
# against the checked-in baseline. Release-only — trace_hash's NDEBUG-gated
# lengths make Debug digests differ, so the baseline is a Release artifact.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_test(NAME trace_hash_baseline
             COMMAND /bin/bash ${PROJECT_SOURCE_DIR}/test/trace_hash_baseline.sh
                               ${PROJECT_SOURCE_DIR}/run
                               $<TARGET_FILE:trace_hash>
                               ${PROJECT_SOURCE_DIR}/test/trace_hash.baseline
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    set_tests_properties(trace_hash_baseline PROPERTIES TIMEOUT 130)
endif()
