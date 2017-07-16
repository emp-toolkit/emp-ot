cmake_minimum_required (VERSION 2.8.11)
project (emp-ot)
set(NAME "emp-ot")

include_directories(${CMAKE_SOURCE_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} cmake/)
set(CMAKE_C_FLAGS "-pthread -Wall -march=native -O3 -maes")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++0x")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -pg -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")

FIND_PACKAGE(emp-tool)
INCLUDE_DIRECTORIES(${EMP-TOOL_INCLUDE_DIRS})

macro (add_test _name)
	add_executable(${_name} "test/${_name}.cpp" ${sources})
	target_link_libraries(${_name}  ${RELIC_LIBRARIES} ${OPENSSL_LIBRARIES} gmp ${EMP-TOOL_LIBRARIES}) 
endmacro()

include_directories(${CMAKE_SOURCE_DIR}/ot)

file(GLOB  headers 
"ot/*.h"
"emp-ot"
)
install(FILES ${headers}  DESTINATION include/${NAME})
install(FILES emp-ot-config.cmake DESTINATION cmake/)

add_test(shot)
add_test(mot)
