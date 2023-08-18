SetFuzzerNoMainLibPath(FUZZER_NO_MAIN_LIBRARY)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/version.c
  ${CMAKE_CURRENT_BINARY_DIR}/version.c
  @ONLY
)

set(LUZER_SOURCES luzer.c
                  fuzzed_data_provider.cc
                  tracer.c
                  counters.c
                  ${CMAKE_CURRENT_BINARY_DIR}/version.c)

add_library(${CMAKE_PROJECT_NAME} SHARED ${LUZER_SOURCES})
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
	${LUA_INCLUDE_DIR}
)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
	${LUA_LIBRARIES}
	-fsanitize=fuzzer-no-link
	${FUZZER_NO_MAIN_LIBRARY}
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
	-fsanitize=fuzzer-no-link
)
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES PREFIX "")

set(custom_mutator_lib_source ${CMAKE_CURRENT_SOURCE_DIR}/custom_mutator_lib.c)
add_library(custom_mutator SHARED ${custom_mutator_lib_source})
target_include_directories(custom_mutator PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(custom_mutator PRIVATE ${LUA_LIBRARIES})
set_target_properties(custom_mutator PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(custom_mutator PROPERTIES SOVERSION 1)

if(ENABLE_TESTING)
  add_subdirectory(tests)
endif()

install(
  TARGETS ${PROJECT_NAME}
  LIBRARY
  DESTINATION "${CMAKE_LIBDIR}/"
  RENAME luzer.so
)

# See description of NAMELINK_SKIP in
# https://cmake.org/cmake/help/latest/command/install.html
install(
  TARGETS custom_mutator
  LIBRARY
  NAMELINK_SKIP
  DESTINATION "${CMAKE_LIBDIR}/"
)
