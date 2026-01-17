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
    COMMENT "Copy libFuzzer and sanitizer libraries"
    COMMAND ${CMAKE_COMMAND} -E copy ${libsanitizer_path} ${libsanitizer_name}
    COMMAND ${CMAKE_COMMAND} -E copy ${libfuzzer_path} ${libfuzzer_name}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )

  set(AR ${CMAKE_C_COMPILER_AR})
  if (NOT EXISTS ${AR})
    set(AR ${CMAKE_AR})
  endif()

  # Strip preinit object files in static libraries, otherwise a message
  # `.preinit_array section is not allowed in DSO` will prevent building DSO.
  add_custom_target(strip_lib_${name}
    COMMENT "Strip sanitizer library ${name}"
    COMMAND ${AR} d ${libsanitizer_name} ${strip}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    BYPRODUCTS ${libsanitizer_name}
    DEPENDS copy_libs_${name}
  )

  add_custom_target(build_dso_${name} ALL
    COMMENT "Build sanitizer library ${name}"
    COMMAND ${CMAKE_C_COMPILER} -Wl,--whole-archive ${libfuzzer_name}
       ${libsanitizer_name} -Wl,--no-whole-archive -lstdc++ -lpthread -ldl
       -shared -o ${sanitizer_dso_name}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    BYPRODUCTS ${sanitizer_dso_name}
    DEPENDS strip_lib_${name}
  )
endmacro()

list(APPEND LIBCLANG_ASAN_STRIP
  asan_preinit.cc.o
  asan_preinit.cpp.o
)
list(APPEND LIBCLANG_UBSAN_STRIP
  ubsan_init_standalone_preinit.cc.o
  ubsan_init_standalone_preinit.cpp.o
)

set(ASAN_DSO "libfuzzer_with_asan.so")
set(UBSAN_DSO "libfuzzer_with_ubsan.so")

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
