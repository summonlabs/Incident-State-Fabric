# Incident State Fabric - DCCP boundary 50
# Copyright 2026 Summon Software Labs.
# Licensed under the Apache License, Version 2.0.

cmake_minimum_required(VERSION 3.25)

project(IncidentStateFabric
        VERSION 1.0.0
        DESCRIPTION "Authoritative incident lifecycle for data centre facilities"
        HOMEPAGE_URL "https://github.com/summonlabs/Incident-State-Fabric"
        LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR
    "Incident State Fabric 1.0.0 is implemented and validated for Windows only. "
    "The platform layer in src/detail/platform.cpp uses Win32 file locking, atomic "
    "replacement, and flush semantics that have no validated equivalent in this tree.")
endif()

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(ISF_BUILD_TESTS "Build the proof suite" ON)
option(ISF_BUILD_TOOLS "Build the demo and benchmark executables" ON)
option(ISF_ENABLE_ASAN "Build with the MSVC AddressSanitizer runtime" OFF)
option(ISF_ENABLE_ANALYZE "Run the MSVC static analyzer over first-party code" OFF)
option(ISF_WARNINGS_AS_ERRORS "Treat first-party warnings as errors" ON)

set(ISF_SOURCES
    src/fabric.cpp
    src/types.cpp
    src/detail/canonical.cpp
    src/detail/crypto.cpp
    src/detail/evaluate.cpp
    src/detail/format.cpp
    src/detail/platform.cpp
    src/detail/request_codec.cpp
    src/detail/state.cpp
    src/detail/store.cpp)

set(ISF_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}" CACHE INTERNAL "repository root")

# Every first-party target gets the same strict, deterministic treatment.
function(isf_configure_target target)
  target_include_directories(${target}
    PUBLIC
      "$<BUILD_INTERFACE:${ISF_ROOT_DIR}/include>"
      "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    PRIVATE
      "${ISF_ROOT_DIR}/src")
  set_target_properties(${target} PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
  if(MSVC)
    target_compile_options(${target} PRIVATE
      /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /external:W0 /external:anglebrackets)
    if(ISF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    if(ISF_ENABLE_ASAN)
      target_compile_options(${target} PRIVATE /fsanitize=address)
      target_link_options(${target} PRIVATE /INCREMENTAL:NO)
    endif()
    if(ISF_ENABLE_ANALYZE)
      target_compile_options(${target} PRIVATE /analyze /analyze:external- /analyze:WX-)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    if(ISF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

add_library(isf STATIC ${ISF_SOURCES})
add_library(isf::isf ALIAS isf)
isf_configure_target(isf)

# ---------------------------------------------------------------------------
# Install and package
# ---------------------------------------------------------------------------

install(TARGETS isf
        EXPORT isfTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/isf DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT isfTargets
        FILE isfTargets.cmake
        NAMESPACE isf::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/isf)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/isfConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/isfConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/isf)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/isfConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
          "${CMAKE_CURRENT_BINARY_DIR}/isfConfig.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/isfConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/isf)

install(FILES LICENSE NOTICE README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})

# ---------------------------------------------------------------------------
# Optional components
# ---------------------------------------------------------------------------

if(ISF_BUILD_TOOLS)
  add_subdirectory(tools)
endif()

if(ISF_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
