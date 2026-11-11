# WipeWitnessGcc - the GCC counterpart of ../CMakeLists.txt's WipeWitness,
# standalone like every other component here.
#
#   cmake -S compiler/wipe-witness/gcc -B ~/vg-build/wipe-witness-gcc -G Ninja \
#         -DCMAKE_CXX_COMPILER=g++-13
#   ninja -C ~/vg-build/wipe-witness-gcc    # -> libWipeWitnessGcc.so
#
# Nothing is built under compiler/. As for WipePinGcc (../../gcc-repair/), the
# plugin must be compiled by the same GCC it loads into, against that GCC's
# plugin headers, which are asked of the compiler itself.

cmake_minimum_required(VERSION 3.20)
project(WipeWitnessGcc CXX)

if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  message(FATAL_ERROR "WipeWitnessGcc: build with g++ (-DCMAKE_CXX_COMPILER=g++-13); "
                      "${CMAKE_CXX_COMPILER_ID} cannot compile GCC's plugin headers")
endif()

if(NOT GCC_PLUGIN_DIR)
  execute_process(
    COMMAND ${CMAKE_CXX_COMPILER} -print-file-name=plugin
    OUTPUT_VARIABLE GCC_PLUGIN_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE _rc)
  if(NOT _rc EQUAL 0 OR NOT EXISTS "${GCC_PLUGIN_DIR}/include/gcc-plugin.h")
    message(FATAL_ERROR "WipeWitnessGcc: no plugin headers at '${GCC_PLUGIN_DIR}/include' "
                        "(install gcc-13-plugin-dev, or pass -DGCC_PLUGIN_DIR=...)")
  endif()
endif()
message(STATUS "WipeWitnessGcc: g++ ${CMAKE_CXX_COMPILER_VERSION}, plugin headers from ${GCC_PLUGIN_DIR}/include")

add_library(WipeWitnessGcc MODULE src/WipeWitnessGcc.cpp)
# GCC's headers as SYSTEM, so that -Wall -Wextra speaks about this component's
# code and not about the host compiler's internals.
target_include_directories(WipeWitnessGcc SYSTEM PRIVATE ${GCC_PLUGIN_DIR}/include)
set_target_properties(WipeWitnessGcc PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF
  PREFIX "lib")
# -fno-rtti: GCC itself is built without RTTI, and the plugin derives from its
# pass classes. The prefix map keeps the source directory out of the binary.
target_compile_options(WipeWitnessGcc PRIVATE -fno-rtti -Wall -Wextra
  -ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=compiler/wipe-witness/gcc)
