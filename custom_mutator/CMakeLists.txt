add_executable(libfuzzer_mutator_test ${CMAKE_CURRENT_SOURCE_DIR}/libfuzzer_mutator.cpp)
target_include_directories(libfuzzer_mutator_test PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(libfuzzer_mutator_test PRIVATE ${LUA_LIBRARIES})
target_compile_options(libfuzzer_mutator_test PUBLIC -Wall -Wextra -Wno-unused-parameter)

add_test(
  NAME mutator_test
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/libfuzzer_mutator_test
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(mutator_test PROPERTIES
  ENVIRONMENT "LIBFUZZER_MUTATOR_LUA_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/libfuzzer_mutator.lua"
  PASS_REGULAR_EXPRESSION "data Hi,Libfuzzer, size 12, max_size 13, seed 98"
)

install(
  FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/libfuzzer_mutator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/libfuzzer_mutator.lua
  DESTINATION ${CMAKE_LIBRARY_PATH}/${PROJECT_NAME}/
)
