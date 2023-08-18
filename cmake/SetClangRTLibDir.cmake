# The function sets the given variable in a parent scope to a
# value in FUZZER_NO_MAIN_LIBRARY environment variable if it
# is set. Otherwise the value with path to a directory with
# libclang_rt.fuzzer_no_main library is composed manually.
# Function raises a fatal message if C compiler is not Clang.
#
# On Linux installations libFuzzer library is typically located at:
#
# /usr/lib/<llvm-version>/lib/clang/<clang-version>/lib/linux/libclang_rt.fuzzer_no_main-<architecture>.a
#
# Location is LLVM_LIBRARY_DIRS/clang/<version>/lib/<OS>/,
# for example LLVM_LIBRARY_DIRS/clang/4.0.0/lib/darwin/.
#
# 1. https://llvm.org/docs/LibFuzzer.html#using-libfuzzer-as-a-library

function(SetFuzzerNoMainLibPath outvar)
  if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR "C compiler is not a Clang")
  endif ()

  set(ClangRTLibDir $ENV{FUZZER_NO_MAIN_LIBRARY})

  if (NOT ClangRTLibDir)
    string(REPLACE "." ";" VERSION_LIST ${CMAKE_C_COMPILER_VERSION})
    list(GET VERSION_LIST 0 CLANG_VERSION_MAJOR)
    # Clang <= 15: /usr/lib/llvm-xxx/lib/clang/X.Y.Z/lib/linux/
    # Clang >  15: /usr/lib/llvm-xxx/lib/clang/X/lib/linux/
    set(CLANG_VERSION ${CMAKE_C_COMPILER_VERSION})
    if (CLANG_VERSION_MAJOR GREATER 15)
      set(CLANG_VERSION ${CLANG_VERSION_MAJOR})
    endif ()

    if (CMAKE_SIZEOF_VOID_P EQUAL 4)
      set(ARCH "i386")
    elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
      set(ARCH "x86_64")
    endif ()

    # find_package(LLVM 17 REQUIRED CONFIG)
    # FIXME: Check presence of LLVM.
    # set(LLVM_BASE "${LLVM_LIBRARY_DIRS}/clang/")

    string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} OS_NAME)

    set(ClangRTLibDir "/usr/lib/clang/${CLANG_VERSION}/lib/${OS_NAME}/libclang_rt.fuzzer_no_main-${ARCH}.a")
  endif ()
  set(${outvar} ${ClangRTLibDir} PARENT_SCOPE)
  message(STATUS "[SetClangRTLibDir] ${outvar} is ${ClangRTLibDir}")
endfunction()
