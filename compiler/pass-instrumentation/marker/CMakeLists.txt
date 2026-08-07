# MarkerPass - standalone CMake project.
#
# Standalone on purpose: there is no top-level CMakeLists in compiler/, because
# the components here are built and measured one at a time by different people,
# and a shared aggregate build turns "my component compiles" into a claim about
# everybody else's.
#
#   cmake -S /mnt/c/Users/PC_User/VibeGuard/compiler/pass-instrumentation/marker \
#         -B ~/vg-build/marker -G Ninja \
#         -DLLVM_DIR=$(llvm-config-18 --cmakedir)
#   ninja -C ~/vg-build/marker
#
# Produces ~/vg-build/marker/libMarkerPass.so.

cmake_minimum_required(VERSION 3.20)
project(MarkerPass LANGUAGES CXX)

# No version argument: LLVM 18's config-version file rejects a bare "18" as
# incompatible with 18.1.3. The tree is selected with -DLLVM_DIR instead.
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in ${LLVM_DIR}")

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND "${LLVM_DEFINITIONS}")
add_definitions(${LLVM_DEFINITIONS_LIST})

add_library(MarkerPass MODULE MarkerPass.cpp)

target_include_directories(MarkerPass SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})

target_compile_features(MarkerPass PRIVATE cxx_std_17)

set_target_properties(MarkerPass PROPERTIES
  CXX_EXTENSIONS OFF
  # The loader resolves LLVM symbols out of the host process (clang), so the
  # plugin must not be linked against LLVM itself. Linking it produces two
  # copies of the pass registry and a plugin that loads and then does nothing.
  PREFIX "lib"
)

# Match the host's RTTI setting or the plugin fails to load with a vtable error.
if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(MarkerPass PRIVATE -fno-rtti)
endif()

# Undefined symbols are expected: they are satisfied by clang at dlopen time.
target_link_options(MarkerPass PRIVATE -Wl,--allow-shlib-undefined)
