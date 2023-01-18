cmake_minimum_required(VERSION 3.10.2)

project(luzer
  LANGUAGES C CXX
  VERSION "0.1.0"
)

find_package(Lua 5.1 REQUIRED)
find_package(LLVM REQUIRED CONFIG)
find_library(LIBRT rt)

set(LUA_NAME "lua${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}")
find_program(LUA_EXECUTABLE "${LUA_NAME}")
if(NOT EXISTS ${LUA_EXECUTABLE})
  message(FATAL_ERROR "${LUA_NAME} is required")
endif()

message(STATUS "Found Lua ${LUA_VERSION_STRING}")
message(STATUS "Found Lua interpreter ${LUA_EXECUTABLE}")
message(STATUS "Found LLVM ${LLVM_VERSION}")

if(${LLVM_PACKAGE_VERSION} VERSION_LESS 5.0.0)
  message(FATAL_ERROR "LLVM 5.0.0 or newer is required")
endif()

if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR
   NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
  message(FATAL_ERROR
      "\n"
      "Building is supported with Clang compiler only.\n"
      " $ rm -rf build\n"
      " $ cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -S . -B build\n"
      " $ cmake --build build --parallel\n"
      "\n")
endif()

if(ENABLE_TESTING AND NOT EXISTS ${LUA_EXECUTABLE})
  message(WARNING "Lua executable is not found, testing is not available.")
endif()

enable_testing()
add_subdirectory(mutator)
add_subdirectory(luzer)

## Install ####################################################################
###############################################################################

if (NOT CMAKE_LUADIR)
  set(CMAKE_LUADIR "${CMAKE_PREFIX_PATH}")
endif()

if (NOT CMAKE_LIBDIR)
  set(CMAKE_LIBDIR "${CMAKE_INCLUDE_PATH}")
endif()

install(
  FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
  DESTINATION ${CMAKE_LUADIR}/doc
)
