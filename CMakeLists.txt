cmake_minimum_required(VERSION 3.10.2)

project(luzer
  LANGUAGES C CXX
  VERSION "1.0.0"
)

option(USE_LUA "Use PUC Rio Lua" OFF)
option(USE_LUAJIT "Use LuaJIT" OFF)
option(LUA_PATCHED "Patch Lua runtime" OFF)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set(CMAKE_INCLUDE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_INCLUDE_PATH})

include(BuildLua)
include(BuildLuaJIT)

if (USE_LUA AND LUA_VERSION)
  build_lua(${LUA_VERSION})
  set(LUA_RUNTIME "PUC Rio Lua")
elseif (USE_LUAJIT AND LUA_VERSION)
  build_luajit(${LUA_VERSION})
  set(LUA_RUNTIME "LuaJIT")
else ()
  include(FindLua)
  find_package(Lua ${LUA_VERSION} REQUIRED)
  set(LUA_RUNTIME "PUC Rio Lua")
endif ()

if(NOT ${LUA_FOUND})
  message(FATAL_ERROR "Lua is not found")
endif()

find_package(LLVM REQUIRED CONFIG)
find_library(LIBRT rt)

message(STATUS "Found ${LUA_RUNTIME} ${LUA_VERSION_STRING} (patches: ${LUA_PATCHED})")
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
  unset(ENABLE_TESTING)
else()
  enable_testing()
endif()

if (ENABLE_TESTING AND LUA_PATCHED)
  add_subdirectory(patches/tests)
endif()

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
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/api.md
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/grammar_based_fuzzing.md
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/index.md
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/test_management.md
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/usage.md
  DESTINATION ${CMAKE_LUADIR}/doc
)
