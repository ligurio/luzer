include(MakeLuaPath)

make_lua_path(LUA_CPATH
  PATHS
  ${PROJECT_BINARY_DIR}/luzer/?.so
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
  NAME luzer_options_jobs_test
  COMMAND ${LUA_EXECUTABLE} -e "a = 1"
          ${CMAKE_CURRENT_SOURCE_DIR}/test_options_2.lua
          -runs=10 -jobs=5
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_options_jobs_test PROPERTIES
  ENVIRONMENT "LUA_CPATH=${LUA_CPATH};LUA_PATH=${LUA_PATH}"
  PASS_REGULAR_EXPRESSION "Job 4 exited with exit code 0"
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

list(APPEND LUAJIT_FRIENDLY_MESSAGES
  "---- TRACE [0-9] start test_luajit_friendly.lua:[0-9]+"
  "---- TRACE [0-9] stop -> loop"
  "---- TRACE [0-9] start [0-9]/[0-9] test_luajit_friendly.lua:[0-9]+"
  "---- TRACE [0-9] stop -> return"
)
add_test(
  NAME luzer_luajit_friendly_test
  COMMAND ${LUA_EXECUTABLE} -jdump=is -Ohotloop=1
          ${CMAKE_CURRENT_SOURCE_DIR}/test_luajit_friendly.lua
          -runs=100
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_luajit_friendly_test PROPERTIES
  ENVIRONMENT "LUA_CPATH=${LUA_CPATH};LUA_PATH=${LUA_PATH}"
  PASS_REGULAR_EXPRESSION "${LUAJIT_FRIENDLY_MESSAGES}"
)
if (NOT LUAJIT_FRIENDLY_MODE)
  set_tests_properties(luzer_luajit_friendly_test PROPERTIES DISABLED TRUE)
endif()

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
add_test(
  NAME luzer_hook_test
  COMMAND ${LUA_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_hook.lua -runs=1
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_hook_test PROPERTIES
  ENVIRONMENT "LUA_CPATH=${LUA_CPATH};LUA_PATH=${LUA_PATH}"
  PASS_REGULAR_EXPRESSION "test_hook.lua:19"
)
