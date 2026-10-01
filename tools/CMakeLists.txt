# Incident State Fabric - DCCP boundary 50
# Copyright 2026 Summon Software Labs.
# Licensed under the Apache License, Version 2.0.

add_executable(isfctl isfctl.cpp)
isf_configure_target(isfctl)
target_link_libraries(isfctl PRIVATE isf::isf)

add_executable(isfbench isfbench.cpp)
isf_configure_target(isfbench)
target_link_libraries(isfbench PRIVATE isf::isf)
