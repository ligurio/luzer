cmake_minimum_required(VERSION 3.10.2)

project(luzer)

find_package(Lua 5.1 REQUIRED)
find_package(LLVM REQUIRED CONFIG)
find_library(LIBRT rt)

find_program(LUA_EXECUTABLE luajit)
if(NOT EXISTS ${LUA_EXECUTABLE})
  find_program(LUA_EXECUTABLE lua)
endif()

message(STATUS "Found Lua ${LUA_VERSION_STRING}")
message(STATUS "Found Lua interpreter ${LUA_EXECUTABLE}")
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")

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

# Locate compiler-rt libraries.
# Location is LLVM_LIBRARY_DIRS/clang/<version>/lib/<OS>/,
# for example LLVM_LIBRARY_DIRS/clang/4.0.0/lib/darwin/.
#
set(LIBCLANG_RT_PATH ${LLVM_LIBRARY_DIRS}/clang/${LLVM_PACKAGE_VERSION}/lib/linux/libclang_rt.fuzzer_no_main-x86_64.a)
if(EXISTS ${LIBCLANG_RT_PATH})
	message(STATUS "Found libclang_rt ${LIBCLANG_RT_PATH}")
else()
  message(FATAL_ERROR "libclang_rt is not found")
endif()

set(LUZER_SOURCES luzer.c
                  fuzzed_data_provider.cc
                  tracer.c)

add_library(${CMAKE_PROJECT_NAME} SHARED ${LUZER_SOURCES})
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${LUA_LIBRARIES} ${LIBRT} ${LIBCLANG_RT_PATH} -fsanitize=fuzzer-no-link)
# target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${LUA_LIBRARIES} ${LIBRT} -fsanitize=fuzzer-no-link /usr/lib/llvm-13/lib/clang/13.0.1/lib/linux/libclang_rt.fuzzer_no_main-x86_64.a)
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic -Wno-unused-parameter -g -fsanitize=fuzzer-no-link)
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES PREFIX "")

## Testing ####################################################################
###############################################################################

add_executable(libfuzzer_mutator_test libfuzzer_mutator.cpp)
target_include_directories(libfuzzer_mutator_test PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(libfuzzer_mutator_test PRIVATE ${LUA_LIBRARIES})
target_compile_options(libfuzzer_mutator_test PUBLIC -Wall -Wextra -Wno-unused-parameter)

if(EXISTS ${LUA_EXECUTABLE})
  enable_testing()
  add_test(
    NAME luzer_test
    COMMAND ${LUA_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test.lua
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
  set_tests_properties(luzer_test PROPERTIES
    ENVIRONMENT "LUA_CPATH='./${CMAKE_CURRENT_BINARY_DIR}/?.so;'")
  add_test(
    NAME mutator_test
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/libfuzzer_mutator_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
  set_tests_properties(mutator_test PROPERTIES
    ENVIRONMENT "LIBFUZZER_MUTATOR_LUA_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/libfuzzer_mutator.lua"
    PASS_REGULAR_EXPRESSION "data Hi,Sergey, size 9, max_size 10, seed 98")
  set(CMAKE_CTEST_ARGUMENTS "--verbose")
else()
  message(WARNING "Lua executable is not found, testing is not available.")
endif()

## Install ####################################################################
###############################################################################

if(NOT LIBDIR STREQUAL "")
  set(CMAKE_LIBRARY_PATH ${LIBDIR})
endif()

if(NOT LUADIR STREQUAL "")
  set(CMAKE_SYSTEM_PREFIX_PATH ${LUADIR})
endif()

install(
  TARGETS ${CMAKE_PROJECT_NAME}
  DESTINATION ${CMAKE_SYSTEM_PREFIX_PATH}
  RENAME luzer.so
)

install(
  FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    ${CMAKE_CURRENT_SOURCE_DIR}/libfuzzer_mutator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/libfuzzer_mutator.lua
  DESTINATION ${CMAKE_LIBRARY_PATH}/${PROJECT_NAME}/
)
