include(MakeLuaPath)

make_lua_path(LUA_CPATH
  PATHS
  ${PROJECT_BINARY_DIR}/luzer/?.so
  ${CMAKE_CURRENT_BINARY_DIR}/?.${CMAKE_SHARED_LIBRARY_SUFFIX}
)

make_lua_path(LUA_PATH
  PATHS
  ${PROJECT_SOURCE_DIR}/?/?.lua
  ${PROJECT_SOURCE_DIR}/?/init.lua
)

add_test(
  NAME luzer_unit_test
  COMMAND ${LUA_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_unit.lua
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_unit_test PROPERTIES
  ENVIRONMENT "LUA_PATH=${LUA_PATH};LUA_CPATH=${LUA_CPATH};"
)

add_test(
  NAME luzer_e2e_test
  COMMAND ${LUA_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_e2e.lua
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_e2e_test PROPERTIES
  ENVIRONMENT "LUA_CPATH=${LUA_CPATH};LUA_PATH=${LUA_PATH}"
  PASS_REGULAR_EXPRESSION "test_e2e.lua:7: assert has triggered"
)

add_test(
  NAME luzer_options_corpus_path_via_table_test
  COMMAND ${LUA_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_options_1.lua
          -max_total_time=1
)
set_tests_properties(luzer_options_corpus_path_via_table_test PROPERTIES
  ENVIRONMENT "LUA_CPATH=${LUA_CPATH};LUA_PATH='${LUA_PATH}'"
  PASS_REGULAR_EXPRESSION
    "ERROR: The required directory \"undefined\" does not exist"
)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/seed_corpus)
add_test(
  NAME luzer_options_corpus_path_via_option_test
  COMMAND ${LUA_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_options_1.lua
          -runs=1 seed_corpus
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_options_corpus_path_via_option_test PROPERTIES
  ENVIRONMENT "LUA_CPATH=${LUA_CPATH};LUA_PATH=${LUA_PATH}"
  PASS_REGULAR_EXPRESSION "0 files found in seed_corpus"
)

add_test(
  NAME luzer_options_seed_via_option_test
  COMMAND ${LUA_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_options_2.lua
          -runs=1 -seed=50
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_options_seed_via_option_test PROPERTIES
  ENVIRONMENT "LUA_CPATH=${LUA_CPATH};LUA_PATH=${LUA_PATH}"
  PASS_REGULAR_EXPRESSION "Seed: 50"
)

add_test(
  NAME luzer_options_help_test
  COMMAND ${LUA_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_options_2.lua
          -help=1
)
set_tests_properties(luzer_options_help_test PROPERTIES
  ENVIRONMENT "LUA_CPATH=${LUA_CPATH};LUA_PATH=${LUA_PATH}"
  PASS_REGULAR_EXPRESSION "Usage:"
)

add_test(
  NAME luzer_custom_mutator_example
  COMMAND ${LUA_EXECUTABLE} "${PROJECT_SOURCE_DIR}/examples/example_custom_mutator.lua"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_custom_mutator_example PROPERTIES
  ENVIRONMENT "LUA_CPATH=${LUA_CPATH};LUA_PATH=${LUA_PATH}"
  PASS_REGULAR_EXPRESSION "example_custom_mutator.lua:19: assert has triggered"
)

add_test(
  NAME luzer_basic_example
  COMMAND ${LUA_EXECUTABLE} "${PROJECT_SOURCE_DIR}/examples/example_basic.lua"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_basic_example PROPERTIES
  ENVIRONMENT "LUA_CPATH=${LUA_CPATH};LUA_PATH=${LUA_PATH}"
  PASS_REGULAR_EXPRESSION "example_custom_mutator.lua:19: assert has triggered"
  DISABLED True
)

add_library(hello SHARED test_hello.c)
target_include_directories(hello PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(hello PRIVATE
    ${LUA_LIBRARIES}
    ${FUZZER_NO_MAIN_LIBRARY}
)
set_target_properties(hello PROPERTIES PREFIX "")
target_compile_options(hello PRIVATE
    # FIXME: ./hello.so: undefined symbol: _ZNSt6thread6_StateD2Ev
    # -fsanitize=fuzzer-no-link
    -fprofile-instr-generate
    -fcoverage-mapping
)

add_test(
  NAME luzer_lua_capi_hello
  COMMAND ${LUA_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/test_hello.lua"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_lua_capi_hello PROPERTIES
  ENVIRONMENT "LUA_CPATH=${LUA_CPATH};LUA_PATH=${LUA_PATH}"
  PASS_REGULAR_EXPRESSION "Crash!"
)

add_library(goodbye SHARED test_goodbye.c)
target_include_directories(goodbye PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(goodbye PRIVATE
    ${FUZZER_NO_MAIN_LIBRARY}
)
target_compile_options(goodbye PRIVATE
    -fsanitize=fuzzer-no-link
    -fprofile-instr-generate
)

add_test(
  NAME luzer_lua_ffi_goodbye
  COMMAND ${LUA_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/test_goodbye.lua"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_lua_ffi_goodbye PROPERTIES
  ENVIRONMENT "LUA_CPATH=${LUA_CPATH};LUA_PATH=${LUA_PATH}"
  PASS_REGULAR_EXPRESSION "Crash!"
)
