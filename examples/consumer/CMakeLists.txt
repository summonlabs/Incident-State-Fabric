# Downstream consumer of the installed Incident State Fabric package.
cmake_minimum_required(VERSION 3.25)
project(isf_consumer LANGUAGES CXX)

find_package(isf 1.0 CONFIG REQUIRED)

add_executable(isf_consumer main.cpp)
target_compile_features(isf_consumer PRIVATE cxx_std_20)
target_link_libraries(isf_consumer PRIVATE isf::isf)
