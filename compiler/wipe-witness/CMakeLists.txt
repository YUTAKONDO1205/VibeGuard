# WipeWitness - standalone CMake project, built on its own like every other
# component here (see compiler/pass-instrumentation/marker/CMakeLists.txt for
# why there is no aggregate build).
#
#   cmake -S compiler/wipe-witness -B ~/vg-build/wipe-witness -G Ninja \
#         -DLLVM_DIR=$(llvm-config-18 --cmakedir)
#   ninja -C ~/vg-build/wipe-witness       # -> libWipeWitness.so
#
# Nothing is built under compiler/. A directory of its own rather than a second
# target in compiler/llvm-repair/CMakeLists.txt, so that building this plugin
# cannot touch how libWipePin.so is built.

cmake_minimum_required(VERSION 3.20)
# C as well as CXX, for the reason compiler/llvm-repair/CMakeLists.txt gives:
# LLVM 15, 16 and 17's LLVMConfig.cmake run check_c_source_compiles. Nothing
# here is compiled as C.
project(WipeWitness C CXX)

# No version argument, as in compiler/llvm-repair: point at the tree with
# -DLLVM_DIR instead.
find_package(LLVM REQUIRED CONFIG)

message(STATUS "WipeWitness: LLVM ${LLVM_PACKAGE_VERSION} from ${LLVM_DIR}")

add_library(WipeWitness MODULE src/WipeWitness.cpp)

# LLVM's headers as SYSTEM, so that -Wall -Wextra speaks about this component's
# code and not about the host's headers.
target_include_directories(WipeWitness SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})

set_target_properties(WipeWitness PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF
  PREFIX "lib")

# The host LLVM is built without RTTI; a plugin that disagrees fails to load
# with an undefined typeinfo rather than with a readable message.
target_compile_options(WipeWitness PRIVATE -fno-rtti -Wall -Wextra)
