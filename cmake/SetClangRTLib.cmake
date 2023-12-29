# The function sets the given variable in a parent scope to a
# value in FUZZER_NO_MAIN_LIBRARY environment variable if it
# is set. Otherwise the value with path to a directory with
# libclang_rt.fuzzer_no_main library is composed manually.
# Function raises a fatal message if C compiler is not Clang.
#
# $ clang-15 -print-file-name=libclang_rt.fuzzer_no_main-x86_64.a
# $ /usr/lib/llvm-15/lib/clang/15.0.7/lib/linux/libclang_rt.fuzzer_no_main-x86_64.a
#
# On Linux installations libFuzzer library is typically located at:
#
# /usr/lib/<llvm-version>/lib/clang/<clang-version>/lib/linux/libclang_rt.fuzzer_no_main-<architecture>.a
#
# 1. https://llvm.org/docs/LibFuzzer.html#using-libfuzzer-as-a-library

function(SetFuzzerNoMainLibPath outvar)
  if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR "C compiler is not a Clang")
  endif ()

  if (CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(ARCH "i386")
  elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH "x86_64")
  else ()
    message(FATAL_ERROR "Unsupported architecture.")
  endif ()

  set(LIB_FUZZER_NO_MAIN "libclang_rt.fuzzer_no_main-${ARCH}.a")
  execute_process(COMMAND ${CMAKE_C_COMPILER} "-print-file-name=${LIB_FUZZER_NO_MAIN}"
    RESULT_VARIABLE CMD_ERROR
    OUTPUT_VARIABLE CMD_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if (CMD_ERROR)
    message(FATAL_ERROR "${CMD_ERROR}")
  endif ()
  set(${outvar} ${CMD_OUTPUT} PARENT_SCOPE)
  message(STATUS "[SetClangRTLib] ${outvar} is ${CMD_OUTPUT}")
endfunction()
