cmake_minimum_required (VERSION 2.8.11)
project (emp-ot)
set(NAME "emp-ot")

if(POLICY CMP0042)
  cmake_policy(SET CMP0042 NEW) # use rpath on macOS
endif()

if(NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

include_directories(${CMAKE_SOURCE_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} cmake/)
set(CMAKE_C_FLAGS "-pthread -Wall -march=native -O3 -maes -mrdseed")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++0x")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
OPTION(USE_RANDOM_DEVICE "Option description" OFF)
IF(USE_RANDOM_DEVICE)
     ADD_DEFINITIONS(-DEMP_USE_RANDOM_DEVICE)
ENDIF(USE_RANDOM_DEVICE)

find_package(emp-tool REQUIRED)
include_directories(${EMP-TOOL_INCLUDE_DIRS})

macro (add_test _name)
	add_executable(${_name} "test/${_name}.cpp" ${sources})
	target_link_libraries(${_name} ${EMP-TOOL_LIBRARIES}) 
endmacro()

install(FILES cmake/emp-ot-config.cmake DESTINATION cmake/)
install(DIRECTORY emp-ot DESTINATION include/)

add_test(shot)
add_test(mot)
