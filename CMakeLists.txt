cmake_minimum_required (VERSION 3.0)
project (emp-ot)
set(NAME "emp-ot")
set (CMAKE_CXX_STANDARD 11) 

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/common.cmake)
include(${CMAKE_FOLDER}/cmake/source_of_randomness.cmake)
include(${CMAKE_FOLDER}/cmake/threading.cmake)

find_package(emp-tool REQUIRED)
find_package(Boost 1.58 REQUIRED random timer)
find_package(Eigen3 3.3 REQUIRED NO_MODULE)
include_directories(${EMP-TOOL_INCLUDE_DIRS} ${EIGEN3_INCLUDE_DIR} ${Boost_INCLUDE_DIRS})

# Installation
install(FILES cmake/emp-ot-config.cmake DESTINATION cmake/)
install(DIRECTORY emp-ot DESTINATION include/)

# Test cases
macro (add_test _name)
	add_test_with_lib(${_name} ${EMP-TOOL_LIBRARIES})
endmacro()

add_test(shot)
add_test(mot)
add_test(deltaot)
add_test(ideal)
add_test(lattice)
#message(BOOST: ${Boost_LIBRARIES})
target_link_libraries(lattice Eigen3::Eigen ${Boost_LIBRARIES})
target_compile_options(lattice PUBLIC -fext-numeric-literals)
SET_TARGET_PROPERTIES(lattice PROPERTIES COMPILE_DEFINITIONS "EMP_USE_RANDOM_DEVICE")
