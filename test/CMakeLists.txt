#Testing macro
macro (add_test_executable_with_lib _name libs)
	add_executable(test_${_name} "${_name}.cpp")
	target_link_libraries(test_${_name} ${OPENSSL_LIBRARIES} ${emp-tool})
endmacro()

macro (add_test_case _name)
	add_test_executable_with_lib(${_name} "")
  	add_test(NAME ${_name} COMMAND test_${_name} WORKING_DIR ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
endmacro()

macro (add_test_case_with_run _name)
	add_test_executable_with_lib(${_name} "")
	add_test(NAME ${_name} COMMAND run "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${_name}")
endmacro()

# Test cases
add_test_case_with_run(ot)
add_test_case_with_run(ferret)
add_test_case(bench_lpn)
