cmake_minimum_required(VERSION 3.10.2)

project(luzer)

find_package(Lua 5.1 REQUIRED)
find_package(LLVM REQUIRED CONFIG)

find_program(LUA_EXECUTABLE luajit)
if(NOT EXISTS ${LUA_EXECUTABLE})
  find_program(LUA_EXECUTABLE lua)
endif()

message(STATUS "Found Lua ${LUA_VERSION_STRING}")
message(STATUS "Found Lua interpreter ${LUA_EXECUTABLE}")
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")

# TODO: check a minimal version of LLVM where FuzzedDataProvider.h is present.

if(CMAKE_COMPILER_IS_GNUCC)
message(FATAL_ERROR
    "\n"
    "Building is unsupported with GCC compiler. Use Clang:\n"
    " $ rm -rf build\n"
    " $ cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -S . -B build\n"
    " $ cmake --build build\n"
    "\n")
endif()

set(LUZER_SOURCES luzer.c
                  fuzzed_data_provider.cc)

add_library(${CMAKE_PROJECT_NAME} SHARED ${LUZER_SOURCES})
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${LUA_LIBRARIES} rt)
target_compile_options(${CMAKE_PROJECT_NAME} PUBLIC -Wall -Wextra -Wno-unused-parameter)
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
endif()

## Install ####################################################################
###############################################################################

install(
  TARGETS ${CMAKE_PROJECT_NAME}
  DESTINATION ${LIBDIR}
  RENAME luzer.so
)

install(
  FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    ${CMAKE_CURRENT_SOURCE_DIR}/libfuzzer_mutator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/libfuzzer_mutator.lua
  DESTINATION ${LUADIR}/${PROJECT_NAME}/
)
