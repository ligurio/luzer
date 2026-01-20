function(SetHwArchString outvar)
  if (CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(hw_arch "i386")
  elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)")
      set(hw_arch "arm64")
    else()
      set(hw_arch "x86_64")
    endif()
  else ()
    message(FATAL_ERROR "Unsupported architecture.")
  endif ()
  set(${outvar} ${hw_arch} PARENT_SCOPE)
endfunction()

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

function(SetClangLibPath lib_name outvar)
  if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR "C compiler is not a Clang")
  endif ()

  execute_process(COMMAND ${CMAKE_C_COMPILER} "-print-file-name=${lib_name}"
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
