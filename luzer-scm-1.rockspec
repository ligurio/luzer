rockspec_format = "3.0"
package = 'luzer'
version = 'scm-1'
source = {
    url = 'git+https://github.com/ligurio/luzer',
    branch = 'master',
}

description = {
    summary = 'A coverage-guided, native Lua fuzzer',
    homepage = 'https://github.com/ligurio/luzer',
    issues_url = "https://github.com/ligurio/luzer/issues",
    maintainer = 'Sergey Bronnikov <estetus@gmail.com>',
    license = 'ISC',
    labels = {
        "testing",
        "fuzzing",
        "libfuzzer",
    },
}

build = {
    type = "cmake",
    variables = {
        LUADIR = "$(LUADIR)",
        LIBDIR = "$(LIBDIR)",
    },
}
