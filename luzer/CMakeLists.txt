SetFuzzerNoMainLibPath(FUZZER_NO_MAIN_LIBRARY)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/version.c
  ${CMAKE_CURRENT_BINARY_DIR}/version.c
  @ONLY
)

set(LUZER_SOURCES luzer.c
                  compat.c
                  fuzzed_data_provider.cc
                  tracer.c
                  counters.c
                  ${CMAKE_CURRENT_BINARY_DIR}/version.c)

add_library(luzer_impl SHARED ${LUZER_SOURCES})
target_include_directories(luzer_impl PRIVATE
    ${LUA_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(luzer_impl PRIVATE
    ${LUA_LIBRARIES}
    -fsanitize=fuzzer-no-link
    ${FUZZER_NO_MAIN_LIBRARY}
)
target_compile_options(luzer_impl PRIVATE
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
if(LUA_HAS_JIT)
    target_compile_definitions(luzer_impl PUBLIC LUA_HAS_JIT)
    if(LUAJIT_FRIENDLY_MODE)
        target_compile_definitions(luzer_impl PUBLIC LUAJIT_FRIENDLY_MODE)
    endif()
endif()
set_target_properties(luzer_impl PROPERTIES PREFIX "")

set(custom_mutator_lib_source ${CMAKE_CURRENT_SOURCE_DIR}/custom_mutator_lib.c)
add_library(custom_mutator SHARED ${custom_mutator_lib_source})
target_include_directories(custom_mutator PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(custom_mutator PRIVATE
  ${LUA_LIBRARIES}
  luzer_impl
)

if(ENABLE_TESTING)
  add_subdirectory(tests)
endif()

install(
  TARGETS luzer_impl
  LIBRARY
  DESTINATION "${CMAKE_LIBDIR}/"
  RENAME luzer.so
)

install(
  TARGETS custom_mutator
  LIBRARY
  DESTINATION "${CMAKE_LIBDIR}/"
)

install(
  FILES ${CMAKE_CURRENT_SOURCE_DIR}/init.lua
  DESTINATION "${CMAKE_LUADIR}/${PROJECT_NAME}"
)
