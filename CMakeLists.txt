cmake_minimum_required (VERSION 3.0)
project (emp-ot)
set(NAME "emp-ot")
set (CMAKE_CXX_STANDARD 11) 

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/common.cmake)
include(${CMAKE_FOLDER}/cmake/source_of_randomness.cmake)
include(${CMAKE_FOLDER}/cmake/threading.cmake)

find_package(emp-tool REQUIRED)
#find_package(Eigen3 3.3 REQUIRED NO_MODULE)
find_package(Boost 1.58 COMPONENTS random)
find_package(Eigen3 3.3 NO_MODULE)
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


#message(STATUS eigen found: ${EIGEN3_FOUND})
#message(STATUS boost found: ${BOOST_RANDOM_LIBRARY})

# get_cmake_property(_variableNames VARIABLES)
# list (SORT _variableNames)
# foreach (_variableName ${_variableNames})
#     message(STATUS "${_variableName}=${${_variableName}}")
# endforeach()

if (Boost_RANDOM_FOUND AND EIGEN3_FOUND)
  message(STATUS "Found Eigen3 and boost random -> Lattice OT will be available")
  set(INCLUDE_LATTICE_OT ON)
  add_test(lattice)
  target_link_libraries(lattice Eigen3::Eigen)

  if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(lattice PUBLIC -fext-numeric-literals)
  endif (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  
  SET_TARGET_PROPERTIES(lattice PROPERTIES COMPILE_DEFINITIONS "EMP_USE_RANDOM_DEVICE")
else(Boost_RANDOM_FOUND AND EIGEN3_FOUND)

  message(STATUS "Not all dependencies met for lattice OT. Lattice OT will not be available. This does not affect other OT implementations. See install_packages_lattice.sh.")
  if (NOT Boost_RANDOM_FOUND)
    message(STATUS "Missing Boost random")
  endif (NOT Boost_RANDOM_FOUND)

  if (NOT EIGEN3_FOUND)
    message(STATUS "Missing Eigen3")
  endif (NOT EIGEN3_FOUND)
  

  set(INCLUDE_LATTICE_OT OFF)

endif(Boost_RANDOM_FOUND AND EIGEN3_FOUND)

configure_file(${CMAKE_SOURCE_DIR}/emp-ot/latticeInclude.h.in ${CMAKE_SOURCE_DIR}/emp-ot/latticeInclude.h @ONLY)
