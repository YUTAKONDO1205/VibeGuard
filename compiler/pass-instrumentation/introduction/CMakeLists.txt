# The introduction observer: an LLVM pass-instrumentation plugin.
#
# Built out of band, never by `npm run build`. See compiler/README.md for why
# this directory is outside the npm workspace globs.
#
#   REPO=$(cd "$(git rev-parse --show-toplevel)" && pwd)
#   cmake -S "$REPO"/compiler/pass-instrumentation/introduction \
#         -B ~/vg-build/pass-introduction -G Ninja \
#         -DLLVM_DIR=$(llvm-config-18 --cmakedir)
#   ninja -C ~/vg-build/pass-introduction
#
# Produces ~/vg-build/pass-introduction/libIntroductionObserver.so.
# `tools/live.sh` does all of that and then measures with it.

cmake_minimum_required(VERSION 3.20)
project(IntroductionObserver LANGUAGES CXX)

# No version argument on purpose: LLVM 18's config-version file rejects a bare
# "18" as incompatible with 18.1.3. Point at the tree with -DLLVM_DIR instead.
find_package(LLVM REQUIRED CONFIG)
message(STATUS "IntroductionObserver: LLVM ${LLVM_PACKAGE_VERSION} from ${LLVM_DIR}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(IntroductionObserver MODULE
  IntroductionObserver.cpp
  Census.cpp
  Config.cpp
)

target_include_directories(IntroductionObserver SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})

separate_arguments(INTRODUCTION_OBSERVER_LLVM_DEFS NATIVE_COMMAND "${LLVM_DEFINITIONS}")
target_compile_options(IntroductionObserver PRIVATE ${INTRODUCTION_OBSERVER_LLVM_DEFS})

# Match the host LLVM. A plugin built with RTTI against an LLVM built without it
# fails at load time with an undefined typeinfo, which reads like a version
# mismatch and is not one.
if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(IntroductionObserver PRIVATE -fno-rtti)
endif()

target_compile_options(IntroductionObserver PRIVATE -Wall -Wextra)

# Deliberately links no LLVM library: the symbols are resolved from the process
# that loads the plugin. Linking libLLVM here would give the plugin its own copy
# of LLVM's globals and command-line registry.
