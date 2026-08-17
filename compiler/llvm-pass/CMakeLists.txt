cmake_minimum_required(VERSION 3.20)
project(IrCheckpoints CXX)

# No version argument to find_package on purpose: LLVM 18's config-version file
# rejects a bare "18" as incompatible with 18.1.3. Point at the tree instead,
# with -DLLVM_DIR=$(llvm-config-18 --cmakedir).
find_package(LLVM REQUIRED CONFIG)

message(STATUS "IrCheckpoints: LLVM ${LLVM_PACKAGE_VERSION} from ${LLVM_DIR}")

add_library(IrCheckpoints MODULE
  src/Record.cpp
  src/Extractors.cpp
  src/MetadataChannel.cpp
  src/DualChannel.cpp
  src/IrCheckpoints.cpp
)

target_include_directories(IrCheckpoints PRIVATE ${LLVM_INCLUDE_DIRS} src)
set_target_properties(IrCheckpoints PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
  # The host LLVM is built without RTTI; a plugin that disagrees fails to load
  # with an undefined typeinfo rather than with a readable message.
  COMPILE_FLAGS "-fno-rtti")
