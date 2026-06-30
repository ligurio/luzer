# The macro generates a target `build_dso_<name>` that builds
# a shared library that contains both libFuzzer and a sanitizer.
#
# name - a sanitizer name, used in messages and as a postfix in
#        generated target names.
# libsanitizer_path - a path to static library with sanitizer.
# libfuzzer_path - a path to a static library with libFuzzer.
# strip - a list with object binaries names that should be stripped
#         from a static library with sanitizer before building
#         shared library.
# sanitizer_dso_name - a file name of resulted shared library.
macro(GEN_BUILD_TARGET name libsanitizer_path libfuzzer_path
                       strip sanitizer_dso_name)
  get_filename_component(libsanitizer_name ${libsanitizer_path} NAME)
  get_filename_component(libfuzzer_name ${libfuzzer_path} NAME)

  add_custom_target(copy_libs_${name}
    COMMENT "Copy sanitizer library ${name}"
    COMMAND ${CMAKE_COMMAND} -E copy ${libsanitizer_path} ${libsanitizer_name}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )

  set(AR ${CMAKE_C_COMPILER_AR})
  if (NOT EXISTS ${AR})
    set(AR ${CMAKE_AR})
  endif()

  # Strip preinit object files in static libraries on Linux,
  # otherwise a message `.preinit_array section is not allowed in
  # DSO` will prevent building DSO.
  add_custom_target(strip_lib_${name}
    COMMENT "Strip sanitizer library ${name}"
    COMMAND ${AR} d ${libsanitizer_name} ${strip}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    BYPRODUCTS ${libsanitizer_name}
    DEPENDS copy_libs_${name}
  )

  set(LINK_COMMAND
    ${CMAKE_C_COMPILER}
    -Wl,--whole-archive
    ${CMAKE_CURRENT_BINARY_DIR}/${libfuzzer_name}
    ${CMAKE_CURRENT_BINARY_DIR}/${libsanitizer_name}
    -Wl,--no-whole-archive
    -lstdc++
    -lpthread
    -ldl
    -shared
    -o ${sanitizer_dso_name}
  )
  if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(LINK_COMMAND
      ${CMAKE_C_COMPILER}
      ${CMAKE_CURRENT_BINARY_DIR}/${libfuzzer_name}
      ${CMAKE_CURRENT_BINARY_DIR}/${libsanitizer_name}
      -lstdc++
      -lpthread
      -dynamiclib
      -o ${sanitizer_dso_name}
    )
  endif()
  add_custom_target(build_dso_${name} ALL
    COMMENT "Build sanitizer library ${name}"
    COMMAND ${LINK_COMMAND}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    BYPRODUCTS ${sanitizer_dso_name}
  )
  add_dependencies(build_dso_${name} copy_libFuzzer)
  if (NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    add_dependencies(build_dso_${name} strip_lib_${name})
  else()
    add_dependencies(build_dso_${name} copy_libs_${name})
  endif()
endmacro()

set(LIBCLANG_ASAN_STRIP "")
set(LIBCLANG_UBSAN_STRIP "")
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND LIBCLANG_ASAN_STRIP
    asan_preinit.cc.o
    asan_preinit.cpp.o
  )
  list(APPEND LIBCLANG_UBSAN_STRIP
    ubsan_init_standalone_preinit.cc.o
    ubsan_init_standalone_preinit.cpp.o
  )
endif()

set(ASAN_DSO "libfuzzer_with_asan${CMAKE_SHARED_LIBRARY_SUFFIX}")
set(UBSAN_DSO "libfuzzer_with_ubsan${CMAKE_SHARED_LIBRARY_SUFFIX}")

get_filename_component(FUZZER_NO_MAIN_LIB_NAME ${FUZZER_NO_MAIN_LIBRARY} NAME)
add_custom_target(copy_libFuzzer
  COMMENT "Copy libFuzzer library"
  COMMAND ${CMAKE_COMMAND} -E copy
    ${FUZZER_NO_MAIN_LIBRARY} ${FUZZER_NO_MAIN_LIB_NAME}
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

GEN_BUILD_TARGET("asan"
  ${LIBCLANG_ASAN_LIB}
  ${FUZZER_NO_MAIN_LIBRARY}
  "${LIBCLANG_ASAN_STRIP}"
  ${ASAN_DSO}
)

GEN_BUILD_TARGET("ubsan"
  ${LIBCLANG_UBSAN_LIB}
  ${FUZZER_NO_MAIN_LIBRARY}
  "${LIBCLANG_UBSAN_STRIP}"
  ${UBSAN_DSO}
)
