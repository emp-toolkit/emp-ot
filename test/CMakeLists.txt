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
add_test_case_with_run(ferret)
add_test_case(bench_lpn)
