add_executable(mutator_basic_test
               ${PROJECT_SOURCE_DIR}/mutator/mutator.c
               ${CMAKE_CURRENT_SOURCE_DIR}/mutator_basic_test.c)
target_include_directories(mutator_basic_test PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(mutator_basic_test PRIVATE ${LUA_LIBRARIES})
target_compile_options(mutator_basic_test PUBLIC -Wall -Wextra -Wno-unused-parameter)

add_executable(mutator_seed_test
               ${PROJECT_SOURCE_DIR}/mutator/mutator.c
               ${CMAKE_CURRENT_SOURCE_DIR}/mutator_seed_test.c)
target_include_directories(mutator_seed_test PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(mutator_seed_test PRIVATE ${LUA_LIBRARIES})
target_compile_options(mutator_seed_test PUBLIC -Wall -Wextra -Wno-unused-parameter)

add_executable(mutator_e2e_test
               ${PROJECT_SOURCE_DIR}/mutator/mutator.c
               ${CMAKE_CURRENT_SOURCE_DIR}/mutator_e2e_test.c)
target_include_directories(mutator_e2e_test PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(mutator_e2e_test PRIVATE ${LUA_LIBRARIES} -fsanitize=address,fuzzer)
target_compile_options(mutator_e2e_test PUBLIC -Wall -Wextra -Wno-unused-parameter)

add_executable(crossover_basic_test
               ${PROJECT_SOURCE_DIR}/mutator/crossover.c
               ${CMAKE_CURRENT_SOURCE_DIR}/crossover_basic_test.c)
target_include_directories(crossover_basic_test PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(crossover_basic_test PRIVATE ${LUA_LIBRARIES})
target_compile_options(crossover_basic_test PUBLIC -Wall -Wextra -Wno-unused-parameter)

add_executable(crossover_seed_test
               ${PROJECT_SOURCE_DIR}/mutator/crossover.c
               ${CMAKE_CURRENT_SOURCE_DIR}/crossover_seed_test.c)
target_include_directories(crossover_seed_test PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(crossover_seed_test PRIVATE ${LUA_LIBRARIES})
target_compile_options(crossover_seed_test PUBLIC -Wall -Wextra -Wno-unused-parameter)

add_executable(crossover_e2e_test
               ${PROJECT_SOURCE_DIR}/mutator/crossover.c
               ${CMAKE_CURRENT_SOURCE_DIR}/crossover_e2e_test.c)
target_include_directories(crossover_e2e_test PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(crossover_e2e_test PRIVATE ${LUA_LIBRARIES} -fsanitize=address,fuzzer)
target_compile_options(crossover_e2e_test PUBLIC -Wall -Wextra -Wno-unused-parameter)

add_test(
  NAME mutator_basic_test
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/mutator_basic_test
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(mutator_basic_test PROPERTIES
  ENVIRONMENT "LIBFUZZER_LUA_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/script_basic.lua"
)

add_test(
  NAME mutator_seed_test
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/mutator_seed_test
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(mutator_seed_test PROPERTIES
  ENVIRONMENT "LIBFUZZER_LUA_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/script_seed.lua"
)

add_test(
  NAME mutator_e2e_test
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/mutator_e2e_test
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(mutator_e2e_test PROPERTIES
  ENVIRONMENT "LIBFUZZER_LUA_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/script_e2e.lua"
  PASS_REGULAR_EXPRESSION "BINGO: Found the target, exiting."
  DISABLED True
)

add_test(
  NAME mutator_no_script_test
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/mutator_basic_test
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(mutator_no_script_test PROPERTIES
  ENVIRONMENT "LIBFUZZER_LUA_SCRIPT=unknown"
  PASS_REGULAR_EXPRESSION "is not accessible"
)

add_test(
  NAME crossover_basic_test
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/crossover_basic_test
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(crossover_basic_test PROPERTIES
  ENVIRONMENT "LIBFUZZER_LUA_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/script_basic.lua"
)

add_test(
  NAME crossover_seed_test
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/crossover_seed_test
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(crossover_seed_test PROPERTIES
  ENVIRONMENT "LIBFUZZER_LUA_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/script_seed.lua"
)

add_test(
  NAME crossover_e2e_test
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/crossover_e2e_test
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(crossover_e2e_test PROPERTIES
  ENVIRONMENT "LIBFUZZER_LUA_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/script_e2e.lua"
  PASS_REGULAR_EXPRESSION "BINGO: Found the target, exiting."
  DISABLED True
)

add_test(
  NAME crossover_no_script_test
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/crossover_basic_test
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(crossover_no_script_test PROPERTIES
  ENVIRONMENT "LIBFUZZER_LUA_SCRIPT=unknown"
  PASS_REGULAR_EXPRESSION "is not accessible"
)
