cmake_minimum_required(VERSION 3.21)
project(emp-ot VERSION 1.0.0 LANGUAGES CXX C)

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

# Native top-level Release builds run the tuning sweep automatically, once
# per build directory (skipped while the build dir already holds a tuned or
# manually overridden tuning_local.h; see docs/performance-tuning.md).
# Debug/unspecified build types, subproject consumers, and cross-compiles
# never auto-tune: the sweep is a measurement of THIS machine's optimized
# code. EMP_OT_AUTO_TUNE selects the policy; EMP_OT_AUTO_TUNE_ACTIVE is the
# effective native-Release gate, kept separate so a cached ON cannot leak
# into a later Debug or cross-build reconfiguration. OFF disables the
# automatic sweep and the legacy-file migration below; a result written by
# the explicit `tune` target still applies until `tune-clean`.
set(_EMP_OT_AUTO_TUNE_ELIGIBLE OFF)
if(PROJECT_IS_TOP_LEVEL AND CMAKE_BUILD_TYPE STREQUAL "Release"
   AND NOT CMAKE_CROSSCOMPILING)
    set(_EMP_OT_AUTO_TUNE_ELIGIBLE ON)
endif()
option(EMP_OT_AUTO_TUNE
    "Run the LOCAL-knob tuning sweep automatically during Release builds when this build directory is untuned"
    ${_EMP_OT_AUTO_TUNE_ELIGIBLE})
set(EMP_OT_AUTO_TUNE_ACTIVE OFF)
if(EMP_OT_AUTO_TUNE AND _EMP_OT_AUTO_TUNE_ELIGIBLE)
    set(EMP_OT_AUTO_TUNE_ACTIVE ON)
elseif(EMP_OT_AUTO_TUNE)
    message(STATUS "emp-ot: EMP_OT_AUTO_TUNE=ON is inactive for this "
                   "non-native-Release configuration; use the explicit "
                   "tune target only when its executable can run on this host")
endif()

# ---------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------
# Local-dev tip: point at a sibling emp-tool build tree with
#   -Demp-tool_DIR=/path/to/emp-tool/build
# or with -DCMAKE_PREFIX_PATH=/path/to/emp-tool/install.
find_package(emp-tool 1.0 REQUIRED)

# ---------------------------------------------------------------------
# Library target
# ---------------------------------------------------------------------
# IKNP and Ferret bodies live in .cpp; the rest of the headers are
# consumed inline.
#
# Verbatim pq-crystals/kyber sources sit in emp-ot/base_ot/mlkem/kyber/;
# the SHAKE / Keccak shim is a single header at emp-ot/base_ot/mlkem/
# symmetric.h. Kyber's poly.c does `#include "symmetric.h"`, so we add
# mlkem/ to the include path PRIVATELY for that resolution.
# Parameterized for ML-KEM-512 via KYBER_K=2 → namespace prefix
# pqcrystals_kyber512_ref_* (scoped to the .c files only so KYBER_K
# doesn't leak into our C++ TUs).
set(KYBER_C_SOURCES
    emp-ot/base_ot/mlkem/kyber/poly.c
    emp-ot/base_ot/mlkem/kyber/polyvec.c
    emp-ot/base_ot/mlkem/kyber/ntt.c
    emp-ot/base_ot/mlkem/kyber/reduce.c
    emp-ot/base_ot/mlkem/kyber/cbd.c
    emp-ot/base_ot/mlkem/kyber/verify.c)

add_library(emp-ot STATIC
    emp-ot/ot_extension/iknp.cpp
    emp-ot/ot_extension/ferret/ferret.cpp
    emp-ot/ot_extension/ferret/silent_ferret.cpp
    emp-ot/ot_extension/softspoken/softspoken.cpp
    emp-ot/base_ot/mlkem/bmm.cpp
    ${KYBER_C_SOURCES})
add_library(emp-ot::emp-ot ALIAS emp-ot)

# Tracks emp-tool's C++20 public contract (it depends on emp-tool transitively).
target_compile_features(emp-ot PUBLIC cxx_std_20)

target_include_directories(emp-ot PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/emp-ot/base_ot/mlkem)

set_source_files_properties(${KYBER_C_SOURCES}
    PROPERTIES COMPILE_DEFINITIONS "KYBER_K=2")

target_include_directories(emp-ot PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_link_libraries(emp-ot PUBLIC emp-tool::emp-tool)

# ---------------------------------------------------------------------
# Per-build-directory tuning overrides
# ---------------------------------------------------------------------
# The LOCAL-knob override header (emp-ot/tuning_local.h) lives in the
# build directory, not the source tree: each build directory owns its
# tuning state, so concurrent build dirs and checkouts cannot see each
# other's overrides, and EMP_OT_AUTO_TUNE=OFF cannot be undermined by a
# stale file. The header always exists — a canonical marked stub means
# shipped defaults — so compiler depfiles track it from the first compile
# and a later `tune` rewrite recompiles exactly the affected TUs. The include
# dir is prepended (BEFORE) so this file shadows any pre-redesign
# source-tree copy. tools/ owns the tune / tune-clean / auto-tune
# targets that write it.
set(EMP_OT_TUNING_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/tuning-include)
set(EMP_OT_TUNING_LOCAL_H ${EMP_OT_TUNING_INCLUDE_DIR}/emp-ot/tuning_local.h)
set(EMP_OT_TUNING_STUB_H ${CMAKE_CURRENT_SOURCE_DIR}/cmake/tuning_local.stub.h)
set(_emp_ot_legacy_tuning ${CMAKE_CURRENT_SOURCE_DIR}/emp-ot/tuning_local.h)
if(NOT EXISTS ${EMP_OT_TUNING_LOCAL_H})
    file(MAKE_DIRECTORY ${EMP_OT_TUNING_INCLUDE_DIR}/emp-ot)
    if(EXISTS ${_emp_ot_legacy_tuning} AND EMP_OT_AUTO_TUNE_ACTIVE)
        # One-time migration from the pre-redesign source-tree location,
        # so an already-tuned machine does not pay a fresh sweep.
        file(COPY_FILE ${_emp_ot_legacy_tuning} ${EMP_OT_TUNING_LOCAL_H})
        message(STATUS "emp-ot: migrated source-tree emp-ot/tuning_local.h "
                       "into ${EMP_OT_TUNING_LOCAL_H}")
    else()
        file(COPY_FILE ${EMP_OT_TUNING_STUB_H} ${EMP_OT_TUNING_LOCAL_H})
    endif()
endif()
if(EXISTS ${_emp_ot_legacy_tuning})
    message(WARNING "emp-ot: source-tree emp-ot/tuning_local.h is no longer "
                    "read by CMake builds (tuning is per build directory); "
                    "delete it, or the tune-clean target will.")
endif()
target_include_directories(emp-ot BEFORE PUBLIC
    $<BUILD_INTERFACE:${EMP_OT_TUNING_INCLUDE_DIR}>)

# ---------------------------------------------------------------------
# Install + export
# ---------------------------------------------------------------------
if(EMP_OT_INSTALL)
    set(_cmake_install_dir ${CMAKE_INSTALL_LIBDIR}/cmake/emp-ot)

    install(TARGETS emp-ot EXPORT emp-otTargets)

    # tuning_local.h is excluded from the glob (a source-tree copy is a
    # pre-redesign leftover) and installed explicitly from the build dir
    # below: the library objects were compiled with exactly that file, so
    # installed consumers see the same configuration as the binary —
    # required, since one knob-adjacent constant sizes class members.
    install(DIRECTORY emp-ot
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING
            PATTERN "tuning_local.h" EXCLUDE
            PATTERN "*.h")

    install(FILES ${EMP_OT_TUNING_LOCAL_H}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/emp-ot)

    # License payload: emp-ot's Apache-2.0 text, the third-party notices,
    # and the vendored Kyber upstream license.
    install(FILES LICENSE THIRD_PARTY_NOTICES.md
        DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/emp-ot)
    install(FILES emp-ot/base_ot/mlkem/kyber/LICENSE
        DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/emp-ot/kyber)

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

    # Build-tree export so siblings can consume without `make install`.
    # Gated on EMP_OT_INSTALL because the emp-otTargets export set is only
    # registered by install(TARGETS ... EXPORT) above; with EMP_OT_INSTALL off
    # (the add_subdirectory case) that set never exists, so an unconditional
    # export() would abort configure. add_subdirectory consumers link the
    # emp-ot::emp-ot ALIAS target directly and need no exported file.
    export(EXPORT emp-otTargets
           NAMESPACE emp-ot::
           FILE      ${CMAKE_CURRENT_BINARY_DIR}/emp-otTargets.cmake)
endif()

# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------
if(EMP_OT_BUILD_TESTS)
    include(CTest)
    add_subdirectory(test)    # correctness tests (ctest)
    add_subdirectory(bench)   # performance benchmarks (build-only)
endif()

# Tuning tool + tune/tune-clean targets (and the Release auto-tune hook,
# EMP_OT_AUTO_TUNE). Top-level only: tuning is a property of the machine
# that builds and runs the standalone repo, never of an embedding parent.
if(PROJECT_IS_TOP_LEVEL)
    add_subdirectory(tools)
endif()
