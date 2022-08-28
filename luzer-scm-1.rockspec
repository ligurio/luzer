package = 'luzer'
version = 'scm-1'
source = {
    url = 'git+https://github.com/ligurio/luzer',
    branch = 'master',
}

description = {
    summary = 'A coverage-guided, native Lua fuzzer',
    detailed = [[ luzer is a coverage-guided Lua fuzzing engine. It supports
fuzzing of Lua code, but also C extensions written for Lua. Luzer is
based off of libFuzzer. When fuzzing native code, luzer can be used in
combination with Address Sanitizer or Undefined Behavior Sanitizer to catch
extra bugs. ]],
    homepage = 'https://github.com/ligurio/luzer',
    maintainer = 'Sergey Bronnikov <estetus@gmail.com>',
    license = 'ISC',
}

build = {
    type = "cmake",
    variables = {
        LUADIR = "$(LUADIR)",
        LIBDIR = "$(LIBDIR)",
        CMAKE_C_COMPILER = "clang",
        CMAKE_CXX_COMPILER = "clang++",
    },
}
