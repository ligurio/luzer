set(LUA_CPATH "\;${PROJECT_BINARY_DIR}/luzer/?.so\;")

add_test(
  NAME luzer_unit_test
  COMMAND ${LUA_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_unit.lua
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_unit_test PROPERTIES
  ENVIRONMENT "LUA_CPATH='${LUA_CPATH}'"
)

add_test(
  NAME luzer_e2e_test
  COMMAND ${LUA_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_e2e.lua
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_e2e_test PROPERTIES
  ENVIRONMENT "LUA_CPATH='${LUA_CPATH}'"
  PASS_REGULAR_EXPRESSION "test_e2e.lua:7: assert has triggered"
)

add_test(
  NAME luzer_options_test
  COMMAND ${LUA_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_options.lua
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_options_test PROPERTIES
  ENVIRONMENT "LUA_CPATH='${LUA_CPATH}'"
  PASS_REGULAR_EXPRESSION "ERROR: The required directory \"undefined\" does not exist"
)

add_test(
  NAME luzer_custom_mutator_example
  COMMAND ${LUA_EXECUTABLE} "${PROJECT_SOURCE_DIR}/examples/example_custom_mutator.lua"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_custom_mutator_example PROPERTIES
  ENVIRONMENT "LUA_CPATH='${LUA_CPATH}'"
  PASS_REGULAR_EXPRESSION "example_custom_mutator.lua:19: assert has triggered"
)

add_test(
  NAME luzer_basic_example
  COMMAND ${LUA_EXECUTABLE} "${PROJECT_SOURCE_DIR}/examples/example_basic.lua"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_basic_example PROPERTIES
  ENVIRONMENT "LUA_CPATH='${LUA_CPATH}'"
  PASS_REGULAR_EXPRESSION "example_custom_mutator.lua:19: assert has triggered"
  DISABLED True
)
