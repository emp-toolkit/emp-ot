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
endfunction()

# Per-primitive correctness drivers (assert via check_*/verify_rcot in test.h).
add_test_case_with_run(test_base_ot)
add_test_case_with_run(test_iknp)
add_test_case_with_run(test_softspoken)
add_test_case_with_run(test_ferret)
add_test_case_with_run(test_silentferret)
add_test_case_with_run(test_f2k_vole)
add_test_case_with_run(test_fp_vole)
add_test_case_with_run(test_choice_seed)

# Wire-equivalence / trace harnesses (self-checking via verify_rcot / digest diff).
add_test_case_with_run(trace_equiv)
add_test_case_with_run(trace_hash)
