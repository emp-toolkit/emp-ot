cmake_minimum_required(VERSION 3.21)
project(emp-ot VERSION 1.0.0 LANGUAGES CXX)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR
        "In-source builds are not allowed. Use a separate build directory:\n"
        "  cmake -B build && cmake --build build")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        Debug Release RelWithDebInfo MinSizeRel)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------
option(EMP_OT_BUILD_TESTS "Build emp-ot tests"            ${PROJECT_IS_TOP_LEVEL})
option(EMP_OT_INSTALL     "Generate install / export rules" ${PROJECT_IS_TOP_LEVEL})

# ---------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------
# Local-dev tip: point at a sibling emp-tool build tree with
#   -Demp-tool_DIR=/path/to/emp-tool/build/release
# or with -DCMAKE_PREFIX_PATH=/path/to/emp-tool/install.
find_package(emp-tool 1.0 REQUIRED)

# ---------------------------------------------------------------------
# Library target
# ---------------------------------------------------------------------
# IKNP and FerretCOT bodies live in .cpp now (no longer header-only) —
# the rest of the headers are still consumed inline.
add_library(emp-ot STATIC
    emp-ot/iknp.cpp
    emp-ot/ferret/ferret_cot.cpp)
add_library(emp-ot::emp-ot ALIAS emp-ot)

target_compile_features(emp-ot PUBLIC cxx_std_17)

target_include_directories(emp-ot PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_link_libraries(emp-ot PUBLIC emp-tool::emp-tool)

# ---------------------------------------------------------------------
# Install + export
# ---------------------------------------------------------------------
if(EMP_OT_INSTALL)
    set(_cmake_install_dir ${CMAKE_INSTALL_LIBDIR}/cmake/emp-ot)

    install(TARGETS emp-ot EXPORT emp-otTargets)

    install(DIRECTORY emp-ot
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING
            PATTERN "*.h")

    install(EXPORT emp-otTargets
        NAMESPACE   emp-ot::
        DESTINATION ${_cmake_install_dir}
        FILE        emp-otTargets.cmake)

    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/emp-ot-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/emp-ot-config.cmake
        INSTALL_DESTINATION ${_cmake_install_dir})

    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/emp-ot-config-version.cmake
        VERSION       ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion)

    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/emp-ot-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/emp-ot-config-version.cmake
        DESTINATION ${_cmake_install_dir})
endif()

# Build-tree export so siblings can consume without `make install`.
export(EXPORT emp-otTargets
       NAMESPACE emp-ot::
       FILE      ${CMAKE_CURRENT_BINARY_DIR}/emp-otTargets.cmake)

# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------
if(EMP_OT_BUILD_TESTS)
    include(CTest)
    add_subdirectory(test)
endif()
