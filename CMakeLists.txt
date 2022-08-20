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

add_library(${CMAKE_PROJECT_NAME} SHARED luzer.c)
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${LUA_LIBRARIES} ${LLVM_LIBRARIES})
target_compile_options(${CMAKE_PROJECT_NAME} PUBLIC -Wall -Wextra -Wno-unused-parameter)
target_compile_options(${CMAKE_PROJECT_NAME} PUBLIC
	$<$<COMPILE_LANGUAGE:CXX>:-std=c++11 -stdlib=libc++ -stdlib=libstdc++>)

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
  set_property(TEST luzer_test PROPERTY ENVIRONMENT "LUA_CPATH='./${CMAKE_CURRENT_BINARY_DIR}/?.so;'")
  add_test(
    NAME mutator_test
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/libfuzzer_mutator_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
  set_property(TEST mutator_test PROPERTY ENVIRONMENT "LIBFUZZER_MUTATOR_LUA_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/libfuzzer_mutator.lua")
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
