# Locate a LuaJIT library.
#
# This module defines:
#  LUA_FOUND, if false, do not try to link to LuaJIT,
#  LUA_LIBRARIES, where to find libluajit,
#  LUA_INCLUDE_DIR, where to find luajit.h,
#  LUA_VERSION_STRING, the version of LuaJIT found,
#  LUA_VERSION_MAJOR, the major version of LuaJIT,
#  LUA_VERSION_MINOR, the minor version of LuaJIT,
#  LUA_VERSION_PATCH, the patch version of LuaJIT.

set(ERROR_MESSAGE "LuaJIT is not found")

find_package(PkgConfig)
pkg_check_modules(PC_LUAJIT luajit)

find_path(LUA_INCLUDE_DIR luajit.h
  HINTS ${PC_LUAJIT_INCLUDEDIR} ${PC_LUAJIT_INCLUDE_DIRS})
if (STATIC_LUAJIT)
  find_library(LUA_LIBRARIES NAMES libluajit-5.1.a
    HINTS ${PC_LUAJIT_LIBDIR} ${PC_LUAJIT_LIBRARY_DIRS})
else()
  find_library(LUA_LIBRARIES NAMES libluajit-5.1${CMAKE_SHARED_LIBRARY_SUFFIX}
    HINTS ${PC_LUAJIT_LIBDIR} ${PC_LUAJIT_LIBRARY_DIRS})
endif()

# $ pkg-config --variable=version luajit
# 2.1.0-beta3
pkg_get_variable(LUA_VERSION_MAJOR luajit majver)
pkg_get_variable(LUA_VERSION_MINOR luajit minver)
pkg_get_variable(LUA_VERSION_PATCH luajit relver)
# Example: ${majver}.${minver}.${relver}-beta3.
pkg_get_variable(LUA_VERSION_STRING luajit version)

include(FindPackageHandleStandardArgs)
# Handle the REQUIRED_VARS argument and set LUA_FOUND to TRUE
# if all listed variables are TRUE.
find_package_handle_standard_args(LuaJIT
  REQUIRED_VARS LUA_LIBRARIES LUA_INCLUDE_DIR
  FOUND_VAR LUAJIT_FOUND
  VERSION_VAR LUA_VERSION_STRING
  FAIL_MESSAGE "${ERROR_MESSAGE}"
)
# Set LUA_FOUND, LUA_INCLUDE_DIR and LUA_LIBRARIES for
# compatibility with FindLua.cmake.
set(LUA_FOUND ${LUAJIT_FOUND})
set(LUA_LIBRARIES ${LUAJIT_LIBRARIES})
set(LUA_INCLUDE_DIR ${LUAJIT_INCLUDE_DIR})
unset(LUAJIT_FOUND)
unset(LUAJIT_LIBRARIES)
unset(LUAJIT_INCLUDE_DIR)

mark_as_advanced(LUA_INCLUDE_DIR LUA_LIBRARIES)
