# WipePin - standalone CMake project, built on its own like every other
# component here (see compiler/pass-instrumentation/marker/CMakeLists.txt for
# why there is no aggregate build).
#
#   cmake -S compiler/llvm-repair -B ~/vg-build/llvm-repair -G Ninja \
#         -DLLVM_DIR=$(llvm-config-18 --cmakedir)
#   ninja -C ~/vg-build/llvm-repair        # -> libWipePin.so
#
# Nothing is built under compiler/.

cmake_minimum_required(VERSION 3.20)
project(WipePin CXX)

# No version argument on purpose: LLVM 18's config-version file rejects a bare
# "18" as incompatible with 18.1.3. Point at the tree with -DLLVM_DIR instead.
find_package(LLVM REQUIRED CONFIG)

message(STATUS "WipePin: LLVM ${LLVM_PACKAGE_VERSION} from ${LLVM_DIR}")

add_library(WipePin MODULE
  src/WipePin.cpp
  src/PinSelector.cpp
  # The canonical JSON writer the observer's records are written with, compiled
  # in unchanged so that both components' records obey interfaces.md section 5
  # through one implementation of it rather than two.
  ../llvm-pass/src/Record.cpp
)

# LLVM's headers as SYSTEM, so that -Wall -Wextra speaks about this component's
# code and not about the host's headers.
target_include_directories(WipePin SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
target_include_directories(WipePin PRIVATE src ../llvm-pass/src)

set_target_properties(WipePin PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF
  PREFIX "lib")

# The host LLVM is built without RTTI; a plugin that disagrees fails to load
# with an undefined typeinfo rather than with a readable message.
target_compile_options(WipePin PRIVATE -fno-rtti -Wall -Wextra)
