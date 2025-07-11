cmake_minimum_required(VERSION 3.10.2)

project(luzer
  LANGUAGES C CXX
  VERSION "1.0.0"
)

option(ENABLE_LUAJIT "Use LuaJIT library" OFF)
option(LUAJIT_FRIENDLY_MODE "Use LuaJIT-friendly mode" OFF)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(SetClangRTLib)

if(LUA_INCLUDE_DIR AND LUA_LIBRARIES)
  # When a path to a Lua library is passed outside, we should
  # mimic a real CMake library to don't break code that depends on
  # LUA_LIBRARIES.
  add_library(liblua STATIC IMPORTED GLOBAL)
  set_target_properties(liblua PROPERTIES
    IMPORTED_LOCATION ${LUA_LIBRARIES})
  set(LUA_LIBRARIES liblua)
elseif(ENABLE_LUAJIT)
  include(FindLuaJIT)
  set(LUA_NAME "luajit")
  find_program(LUA_EXECUTABLE "${LUA_NAME}")
  if(NOT EXISTS ${LUA_EXECUTABLE})
    message(FATAL_ERROR "`${LUA_NAME}` is required")
  endif()
  set(LUA_HAS_JIT ON CACHE INTERNAL "Use LuaJIT library")
  message(STATUS "Found LuaJIT ${LUA_VERSION_STRING}")
  message(STATUS "Found LuaJIT interpreter ${LUA_EXECUTABLE}")
else()
  find_package(Lua 5.1 REQUIRED)
  set(LUA_NAME "lua${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}")
  find_program(LUA_EXECUTABLE "${LUA_NAME}")
  if(NOT EXISTS ${LUA_EXECUTABLE})
    message(FATAL_ERROR "${LUA_NAME} is required")
  endif()
  message(STATUS "Found Lua ${LUA_VERSION_STRING}")
  message(STATUS "Found Lua interpreter ${LUA_EXECUTABLE}")
endif()

if(LUAJIT_FRIENDLY_MODE AND NOT LUA_HAS_JIT)
  message(FATAL_ERROR "LuaJIT-friendly mode requires option ENABLE_LUAJIT")
endif()

find_package(LLVM REQUIRED CONFIG)

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
