cmake_minimum_required (VERSION 3.0)
project (emp-ot)
set(NAME "emp-ot")

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/common.cmake)
include(${CMAKE_FOLDER}/cmake/source_of_randomness.cmake)
include(${CMAKE_FOLDER}/cmake/threading.cmake)

find_package(emp-tool REQUIRED)
find_package(Eigen3 3.3 REQUIRED NO_MODULE)
find_package(dgs REQUIRED)
include_directories(${EMP-TOOL_INCLUDE_DIRS} ${EIGEN3_INCLUDE_DIR} ${DGS_INCLUDE_DIR})

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
target_link_libraries(lattice Eigen3::Eigen)
target_link_libraries(lattice dgs)
SET_TARGET_PROPERTIES(lattice PROPERTIES COMPILE_DEFINITIONS "EMP_USE_RANDOM_DEVICE")
