# WipePinGcc - standalone CMake project, built on its own like every other
# component here (see compiler/pass-instrumentation/marker/CMakeLists.txt for
# why there is no aggregate build).
#
#   cmake -S compiler/gcc-repair -B ~/vg-build/gcc-repair -G Ninja \
#         -DCMAKE_CXX_COMPILER=g++-13
#   ninja -C ~/vg-build/gcc-repair          # -> libWipePinGcc.so, canon-vectors
#   ~/vg-build/gcc-repair/canon-vectors compiler/evidence/testdata/digest-vectors.json
#
# Nothing is built under compiler/.
#
# The plugin must be compiled by the same GCC it loads into, against that GCC's
# plugin headers: GCC checks the version at load (plugin_default_version_check)
# and the plugin API is the compiler's internals, not a stable interface. The
# header directory is asked of the compiler itself rather than spelled out.

cmake_minimum_required(VERSION 3.20)
project(WipePinGcc CXX)

if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  message(FATAL_ERROR "WipePinGcc: build with g++ (-DCMAKE_CXX_COMPILER=g++-13); "
                      "${CMAKE_CXX_COMPILER_ID} cannot compile GCC's plugin headers")
endif()

if(NOT GCC_PLUGIN_DIR)
  execute_process(
    COMMAND ${CMAKE_CXX_COMPILER} -print-file-name=plugin
    OUTPUT_VARIABLE GCC_PLUGIN_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE _rc)
  if(NOT _rc EQUAL 0 OR NOT EXISTS "${GCC_PLUGIN_DIR}/include/gcc-plugin.h")
    message(FATAL_ERROR "WipePinGcc: no plugin headers at '${GCC_PLUGIN_DIR}/include' "
                        "(install gcc-13-plugin-dev, or pass -DGCC_PLUGIN_DIR=...)")
  endif()
endif()
message(STATUS "WipePinGcc: g++ ${CMAKE_CXX_COMPILER_VERSION}, plugin headers from ${GCC_PLUGIN_DIR}/include")

# The canonical-JSON writer and the configuration reader include no GCC header,
# so the digest calibration can build and run without them.
add_library(wpgcore STATIC src/Canon.cpp src/Config.cpp)
set_target_properties(wpgcore PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(wpgcore PUBLIC src)

add_library(WipePinGcc MODULE src/WipePinGcc.cpp)
target_link_libraries(WipePinGcc PRIVATE wpgcore)
# GCC's headers as SYSTEM, so that -Wall -Wextra speaks about this component's
# code and not about the host compiler's internals.
target_include_directories(WipePinGcc SYSTEM PRIVATE ${GCC_PLUGIN_DIR}/include)

add_executable(canon-vectors test/canon-vectors.cpp)
target_link_libraries(canon-vectors PRIVATE wpgcore)

foreach(t wpgcore WipePinGcc canon-vectors)
  set_target_properties(${t} PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF)
  # -fno-rtti: GCC itself is built without RTTI, and the plugin derives from
  # its pass classes. The prefix map keeps the source directory, which names
  # the machine it was built on, out of the binary (gcc_assert and friends
  # expand __FILE__).
  target_compile_options(${t} PRIVATE -fno-rtti -Wall -Wextra
    -ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=compiler/gcc-repair)
endforeach()

set_target_properties(WipePinGcc PROPERTIES PREFIX "lib")
