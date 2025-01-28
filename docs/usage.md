## Usage

### Fuzzing targets

In general, `luzer` has an ability to write fuzzing tests for a Lua functions.
However, steps may depend on implementation of function under test. Let's
consider a three cases:

- Fuzzing a Lua function implemented in Lua
- Fuzzing a Lua function implemented in Lua C
- Fuzzing a shared library via FFI

#### Fuzzing a module written in Lua

Let's create a fuzzing test for a parser of Lua source code used in `luacheck`
module.

Setup a target module using `luarocks`:

```sh
$ luarocks install --local luacheck
```

Create a file `luacheck_parser_parse.lua` with fuzzing target:

```lua
local parser = require("src.luacheck.parser")
local decoder = require("luacheck.decoder")
local luzer = require("luzer")

local function TestOneInput(buf)
    parser.parse(decoder.decode(buf))
end

luzer.Fuzz(TestOneInput, nil, {})
```

Execute test with PUC Rio Lua:

```
$ lua luacheck_parser_parse.lua
```

#### Fuzzing a function implemented in Lua C

Lua functions could be implemented using so called Lua C API. Functions built
in Lua runtime, external modules written in C/C++ are such examples. Learn more
about Lua C API in chapter ["24 – An Overview of the C API
"][programming-in-lua-24] of "Programming in Lua" book.

Setup module using `luarocks`:

```sh
$ luarocks install --tree modules --lua-version 5.1 lua-cjson CC="clang" CFLAGS="-ggdb -fPIC -fsanitize=address" LDFLAGS="-fsanitize=address"

Installing https://luarocks.org/lua-cjson-2.1.0.6-1.src.rock

lua-cjson 2.1.0.6-1 depends on lua >= 5.1 (5.1-1 provided by VM)
clang -ggdb -fPIC -fsanitize=address -I/usr/include/lua5.1 -c lua_cjson.c -o lua_cjson.o
clang -ggdb -fPIC -fsanitize=address -I/usr/include/lua5.1 -c strbuf.c -o strbuf.o
clang -ggdb -fPIC -fsanitize=address -I/usr/include/lua5.1 -c fpconv.c -o fpconv.o
gcc -shared -o cjson.so lua_cjson.o strbuf.o fpconv.o
No existing manifest. Attempting to rebuild...
lua-cjson 2.1.0.6-1 is now installed in /home/sergeyb/sources/luzer/build/modules (license: MIT)
```

Setup environment and execute test:

```sh
$ export LUA_PATH="$LUA_PATH;modules/lib/lua/5.1/?.lua"
$ export LUA_CPATH="$LUA_CPATH;modules/lib/lua/5.1/?.so;./?.so"
$ mkdir cjson-corpus
$ echo -n "{}" > cjson-corpus/sample
$ luajit luzer_example_json.lua
```

This way could be used for fuzzing Lua runtime. Let's consider a fuzzing
target: Lear more about function `loadstring()` in chapter [8 – Compilation,
Execution, and Errors][programming-in-lua-8] of "Programming in Lua" book.

```lua
local luzer = require("luzer")

local function TestOneInput(buf)
    assert(loadstring(buf)) ()
end

local args = {
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
```

Run fuzzing target with instrumented Lua runtime.

#### Fuzzing a shared library via FFI

Lua has a FFI library that allows seamless integration with C/C++ libraries.
LuaJIT has a builtin [FFI library][ffi-library-url], that allows calling
external C functions and using C data structures from pure Lua code.
FFI library allows using `luzer` for fuzzing shared libraries.

Example `examples/example_zlib.lua` demonstrates a test for ZLib library using
FFI. For better results it is recommended to build ZLib with sanitizers.

Run fuzzing target:

```sh
$ lua examples/example_zlib.lua
```

[ffi-library-url]: https://luajit.org/ext_ffi.html
[programming-in-lua-8]: https://www.lua.org/pil/8.html
[programming-in-lua-24]: https://www.lua.org/pil/24.html
[atheris-native-extensions]: https://github.com/google/atheris/blob/master/native_extension_fuzzing.md
[atheris-native-extensions-video]: https://www.youtube.com/watch?v=oM-7lt43-GA
