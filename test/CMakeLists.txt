function(add_test_case name)
    add_executable(test_${name} ${name}.cpp)
    target_link_libraries(test_${name} PRIVATE emp-ot::emp-ot)
    add_test(NAME ${name}
             COMMAND test_${name}
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endfunction()

function(add_test_case_with_run name)
    add_executable(test_${name} ${name}.cpp)
    target_link_libraries(test_${name} PRIVATE emp-ot::emp-ot)
    add_test(NAME ${name}
             COMMAND ${PROJECT_SOURCE_DIR}/run $<TARGET_FILE:test_${name}>
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endfunction()

add_test_case_with_run(ot)
add_test_case_with_run(sfrot)
add_test_case_with_run(ferret)
add_test_case_with_run(softspoken)
add_test_case(bench_lpn)
add_test_case(bench_aes_batch)
add_test_case(bench_cggm)
add_test_case(bench_breakdown)
add_test_case(bench_cggm_tile)
add_test_case(bench_ferret_phase)
add_test_case(bench_conv)
add_test_case(bench_multikey_aes)
add_test_case(bench_sfvole_v2)
add_test_case(bench_softspoken_phase)
add_test_case(prof_sfvole_local)

# Verification harness for the ferret refactor: not added to CTest
# (it has a two-step snap+trace flow driven by hand). Just builds.
add_executable(test_ferret_trace ferret_trace.cpp)
target_link_libraries(test_ferret_trace PRIVATE emp-ot::emp-ot)
