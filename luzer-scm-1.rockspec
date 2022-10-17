package = "luzer"
version = "scm-1"
source = {
    url = "git+https://github.com/ligurio/luzer",
    branch = "master",
}

description = {
    summary = "A coverage-guided, native Lua fuzzer",
    detailed = [[ luzer is a coverage-guided Lua fuzzing engine. It supports
fuzzing of Lua code, but also C extensions written for Lua. Luzer is based off
of libFuzzer. When fuzzing native code, luzer can be used in combination with
Address Sanitizer or Undefined Behavior Sanitizer to catch extra bugs. ]],
    homepage = "https://github.com/ligurio/luzer",
    maintainer = "Sergey Bronnikov <estetus@gmail.com>",
    license = "ISC",
}

dependencies = {
    "lua >= 5.1",
}

build = {
    type = "cmake",
    -- https://github.com/luarocks/luarocks/wiki/Config-file-format#variables
    variables = {
        CMAKE_LUADIR = "$(LUADIR)",
        CMAKE_LIBDIR = "$(LIBDIR)",
        CMAKE_BUILD_TYPE = "RelWithDebInfo",
        CMAKE_C_COMPILER = "clang",
        CMAKE_CXX_COMPILER = "clang++",
    },
}
