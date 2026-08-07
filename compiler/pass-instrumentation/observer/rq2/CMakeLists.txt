# The synthetic ground-truth plugin for the pass-observer accuracy harness.
# Measurement instrument, outside the repository on purpose: it mutates IR.

cmake_minimum_required(VERSION 3.20)
project(SyntheticGroundTruth LANGUAGES CXX)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "SyntheticGroundTruth: LLVM ${LLVM_PACKAGE_VERSION} from ${LLVM_DIR}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(SyntheticGroundTruth MODULE SyntheticGroundTruth.cpp)
target_include_directories(SyntheticGroundTruth SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
separate_arguments(SGT_LLVM_DEFS NATIVE_COMMAND "${LLVM_DEFINITIONS}")
target_compile_options(SyntheticGroundTruth PRIVATE ${SGT_LLVM_DEFS})
if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(SyntheticGroundTruth PRIVATE -fno-rtti)
endif()
target_compile_options(SyntheticGroundTruth PRIVATE -Wall -Wextra)
