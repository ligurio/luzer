# Locate compiler-rt libraries.
# Location is LLVM_LIBRARY_DIRS/clang/<version>/lib/<OS>/,
# for example LLVM_LIBRARY_DIRS/clang/4.0.0/lib/darwin/.
#
# See https://llvm.org/docs/LibFuzzer.html#using-libfuzzer-as-a-library

set(LLVM_BASE ${LLVM_LIBRARY_DIRS}/clang/${LLVM_PACKAGE_VERSION})
string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} OS_NAME)
set(LIBCLANG_RT ${LLVM_BASE}/lib/${OS_NAME}/libclang_rt.fuzzer_no_main-x86_64.a)
if(EXISTS ${LIBCLANG_RT})
  message(STATUS "Found libclang_rt ${LIBCLANG_RT}")
else()
  message(FATAL_ERROR "libclang_rt is not found")
endif()

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/version.c
  ${CMAKE_CURRENT_BINARY_DIR}/version.c
  @ONLY
)

set(LUZER_SOURCES luzer.c
                  fuzzed_data_provider.cc
                  tracer.c
                  ${CMAKE_CURRENT_BINARY_DIR}/version.c)

add_library(${CMAKE_PROJECT_NAME} SHARED ${LUZER_SOURCES})
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
	${LUA_INCLUDE_DIR}
)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
	${LUA_LIBRARIES}
	${LIBRT}
	${LIBCLANG_RT}
	-fsanitize=fuzzer-no-link
)
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE
	-D_FORTIFY_SOURCE=2
	-fpie
	-fPIC
	-Wall
	-Wextra
	-Werror
	-Wpedantic
	-Wno-unused-parameter
	-pedantic
	-g
	-fsanitize=fuzzer-no-link
)
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES PREFIX "")

set(custom_mutator_lib_source ${CMAKE_CURRENT_SOURCE_DIR}/custom_mutator_lib.c)
add_library(custom_mutator SHARED ${custom_mutator_lib_source})
target_include_directories(custom_mutator PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(custom_mutator PRIVATE ${LUA_LIBRARIES})
set_target_properties(custom_mutator PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(custom_mutator PROPERTIES SOVERSION 1)

add_test(
  NAME luzer_unit_test
  COMMAND ${LUA_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_unit.lua
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_unit_test PROPERTIES
  ENVIRONMENT "LUA_CPATH='./${CMAKE_CURRENT_BINARY_DIR}/?.so;'"
)

add_test(
  NAME luzer_e2e_test
  COMMAND ${LUA_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_e2e.lua
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
set_tests_properties(luzer_e2e_test PROPERTIES
  ENVIRONMENT "LUA_CPATH='./${CMAKE_CURRENT_BINARY_DIR}/?.so;'"
  PASS_REGULAR_EXPRESSION "test_e2e.lua:9: assertion failed"
)

install(
  TARGETS ${PROJECT_NAME}
  LIBRARY
  DESTINATION "${CMAKE_LIBDIR}/"
  RENAME luzer.so
)

install(
  TARGETS custom_mutator
  LIBRARY
  DESTINATION "${CMAKE_LIBDIR}/"
)
