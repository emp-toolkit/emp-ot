cmake_minimum_required (VERSION 2.8.11)
project (emp-ot)
set(NAME "emp-ot")

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/ot)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} cmake/)
FIND_PACKAGE(emp-tool)
INCLUDE_DIRECTORIES(${EMP-TOOL_INCLUDE_DIRS})

set (CMAKE_C_FLAGS "-pthread -Wall -march=native -O3 -maes")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pg -ggdb")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++0x")

add_executable(shot test/shot.cpp)
target_link_libraries(shot  relic  ${OPENSSL_LIBRARIES} gmp ${EMP-TOOL_LIBRARIES}) 

add_executable(mot test/mot.cpp)
target_link_libraries(mot  relic  ${OPENSSL_LIBRARIES} gmp ${EMP-TOOL_LIBRARIES}) 

add_executable(iter_ot test/iter_ot.cpp)
target_link_libraries(iter_ot  relic  ${OPENSSL_LIBRARIES} gmp ${EMP-TOOL_LIBRARIES}) 

install(FILES emp-ot-config.cmake DESTINATION cmake/)

file(GLOB  headers 
"ot/*.h"
"emp-ot"
)
install(FILES ${headers}  DESTINATION include/${NAME})
