# Incident State Fabric - DCCP boundary 50
# Copyright 2026 Summon Software Labs.
# Licensed under the Apache License, Version 2.0.

add_executable(isf_tests
    test_framework.cpp
    test_support.cpp
    support/store_builder.cpp
    support/process_util.cpp
    unit_crypto_canonical.cpp
    unit_types.cpp
    unit_authority.cpp
    unit_lifecycle.cpp
    unit_gates.cpp
    unit_idempotency.cpp
    unit_persistence.cpp
    unit_corruption.cpp
    unit_adversarial.cpp
    prop_state_machine.cpp
    ts_concurrency.cpp
    mp_multiprocess.cpp)

isf_configure_target(isf_tests)
target_include_directories(isf_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(isf_tests PRIVATE isf::isf)
target_compile_definitions(isf_tests PRIVATE ISF_CTL_EXECUTABLE="$<TARGET_FILE:isfctl>")
add_dependencies(isf_tests isfctl)

add_test(NAME isf_suite COMMAND isf_tests)
set_tests_properties(isf_suite PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
