cmake_minimum_required(VERSION 3.20)
project(IntentGate CXX)

# `find_package(LLVM REQUIRED CONFIG)` takes no version argument: LLVM 18's
# config-version file rejects a bare `18` as incompatible with `18.1.3`
# (interfaces.md §1). Point at the tree with -DLLVM_DIR / -DClang_DIR instead:
#
#   cmake -S compiler/clang-plugin -B ~/vg-build/clang-plugin -G Ninja \
#         -DCMAKE_CXX_COMPILER=clang++-18 \
#         -DLLVM_DIR=$(llvm-config-18 --cmakedir) \
#         -DClang_DIR=/usr/lib/llvm-18/lib/cmake/clang
find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

message(STATUS "IntentGate: LLVM ${LLVM_PACKAGE_VERSION} (${LLVM_DIR})")
message(STATUS "IntentGate: Clang (${Clang_DIR})")

add_library(IntentGate MODULE
  src/Canonical.cpp
  src/Findings.cpp
  src/Classifier.cpp
  src/Derivation.cpp
  src/IntentGate.cpp
)

target_include_directories(IntentGate SYSTEM PRIVATE
  ${LLVM_INCLUDE_DIRS}
  ${CLANG_INCLUDE_DIRS}
)
target_include_directories(IntentGate PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(IntentGate PRIVATE ${LLVM_DEFINITIONS})

set_target_properties(IntentGate PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF
  PREFIX "lib"
)

# -fno-rtti is not optional. LLVM and Clang are built without RTTI, so a plugin
# built with it fails to link (or, worse, links and then cannot resolve the
# typeinfo the registry needs at dlopen time).
target_compile_options(IntentGate PRIVATE
  -fno-rtti
  -fvisibility-inlines-hidden
  -Wall -Wextra
)

# Deliberately links nothing from LLVM/Clang. The plugin is dlopen'd into a
# clang process that already has libclang-cpp / libLLVM resolved, and linking a
# second copy of either into the module is how a plugin ends up with two
# command-line option registries and aborts at load. Undefined symbols in a
# MODULE library are resolved from the host process at dlopen time; the load
# test in README.md is what proves that actually happens on this toolchain.
if(NOT DEFINED IntentGate_ALLOW_LINK)
  set_target_properties(IntentGate PROPERTIES LINK_FLAGS "")
endif()
