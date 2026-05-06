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

add_test_case_with_run(base_ot)
add_test_case(bench_lpn)
add_test_case(bench_cggm)
add_test_case(bench_sfvole_v2)
add_test_case(prof_sfvole_local)
add_test_case_with_run(bench_ot_extension)
add_test_case_with_run(bench_iknp_rcot)
add_test_case_with_run(bench_softspoken_rcot)
add_test_case_with_run(bench_ferret_rcot)
add_test_case_with_run(trace_equiv)
