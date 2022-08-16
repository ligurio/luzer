package = 'luzer'
version = 'scm-1'
source = {
    url = 'git+https://github.com/ligurio/luzer',
    branch = 'master',
}

description = {
    summary = 'A coverage-guided, native Lua fuzzer',
    homepage = 'https://github.com/ligurio/luzer',
    maintainer = 'Sergey Bronnikov <estetus@gmail.com>',
    license = 'ISC',
}

dependencies = {
    'lua >= 5.1',
}

--[[
build = {
    type = 'make',
    -- Nothing to build.
    build_pass = false,
    variables = {
        LUADIR='$(LUADIR)',
    },
    copy_directories = {
    },
}
]]

build = {
  type = "builtin",
  modules = {
    hello = {
      sources = {"luzer.c"}
    }
  }
}
