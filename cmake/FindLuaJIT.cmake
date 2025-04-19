# Locate a LuaJIT library.
#
# This module defines:
#  LUA_FOUND, if false, do not try to link to Lua,
#  LUA_LIBRARIES, both lua and lualib,
#  LUA_INCLUDE_DIR, where to find lua.h,
#  LUA_VERSION_STRING, the version of Lua found,
#  LUA_VERSION_MAJOR, the major version of Lua,
#  LUA_VERSION_MINOR, the minor version of Lua,
#  LUA_VERSION_PATCH, the patch version of Lua.

set(ERROR_MESSAGE "LuaJIT is not found")

find_package(PkgConfig)
pkg_check_modules(PC_LUAJIT luajit)

find_path(LUA_INCLUDE_DIR luajit.h
  HINTS ${PC_LUAJIT_INCLUDEDIR} ${PC_LUAJIT_INCLUDE_DIRS})
if (STATIC_LUAJIT)
  find_library(LUA_LIBRARIES NAMES libluajit-5.1.a
    HINTS ${PC_LUAJIT_LIBDIR} ${PC_LUAJIT_LIBRARY_DIRS})
else()
  find_library(LUA_LIBRARIES NAMES libluajit-5.1.so
    HINTS ${PC_LUAJIT_LIBDIR} ${PC_LUAJIT_LIBRARY_DIRS})
endif()

if (APPLE)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}
    ${LUA_LIBRARIES} -pagezero_size 10000 -image_base 100000000")
endif()

# $ pkg-config --variable=version luajit
# 2.1.0-beta3
pkg_get_variable(LUA_VERSION_MAJOR luajit majver)
pkg_get_variable(LUA_VERSION_MINOR luajit minver)
pkg_get_variable(LUA_VERSION_PATCH luajit relver)
# ${majver}.${minver}.${relver}-beta3
pkg_get_variable(LUA_VERSION_STRING luajit version)

include(FindPackageHandleStandardArgs)
# Handle the QUIETLY and REQUIRED arguments and set LUA_FOUND to
# TRUE if all listed variables are TRUE.
find_package_handle_standard_args(LuaJIT
  REQUIRED_VARS LUA_LIBRARIES LUA_INCLUDE_DIR
  VERSION_VAR LUA_VERSION_STRING
  FAIL_MESSAGE "${ERROR_MESSAGE}"
)

mark_as_advanced(LUA_INCLUDE_DIR LUA_LIBRARIES)
