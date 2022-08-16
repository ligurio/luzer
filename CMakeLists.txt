cmake_minimum_required(VERSION 3.10.2)

project(luzer)

find_package(Lua 5.1 REQUIRED)
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found Lua  ${LUA_VERSION_STRING}")
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

#### luaL_loadbuffer()

add_executable(luaL_loadbuffer luaL_loadbuffer.c)
target_include_directories(luaL_loadbuffer PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(luaL_loadbuffer PRIVATE ${LUA_LIBRARIES} -fsanitize=fuzzer)
target_compile_options(luaL_loadbuffer PUBLIC -Wall -Wextra -Wno-unused-parameter -fsanitize=fuzzer)
target_compile_options(luaL_loadbuffer PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)

#### LibFuzzer Lua custom mutator example

add_executable(libfuzzer_mutator_example libfuzzer_mutator_example.cpp)
target_link_libraries(libfuzzer_mutator_example PRIVATE -fsanitize=fuzzer)
target_compile_options(libfuzzer_mutator_example PUBLIC -Wall -Wextra -Wno-unused-parameter -fsanitize=fuzzer)
target_compile_options(libfuzzer_mutator_example PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)

#### LibFuzzer Lua custom mutator test

add_executable(libfuzzer_mutator_test libfuzzer_mutator.cpp)
target_include_directories(libfuzzer_mutator_test PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(libfuzzer_mutator_test PRIVATE ${LUA_LIBRARIES})
target_compile_options(libfuzzer_mutator_test PUBLIC -Wall -Wextra -Wno-unused-parameter)
target_compile_options(libfuzzer_mutator_test PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)

#### luzer

add_library(luzer SHARED luzer.c)
target_include_directories(luzer PRIVATE ${LUA_INCLUDE_DIR} ${LLVM_INCLUDE_DIRS} /usr/include/x86_64-linux-gnu/c++/11/)
target_link_libraries(luzer PRIVATE ${LUA_LIBRARIES} ${LLVM_LIBRARIES})
target_compile_options(luzer PUBLIC -Wall -Wextra -Wno-unused-parameter)
target_compile_options(luzer PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++11 -stdlib=libc++ -stdlib=libstdc++ -pedantic -Wall>)
