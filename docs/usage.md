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
CFLAGS="-ggdb -fPIC -fsanitize=address -fsanitize=fuzzer-no-link"
LDFLAGS="-fsanitize=address"
$ luarocks install --local --lua-version 5.1 lua-cjson CC="clang" CFLAGS=$CFLAGS LDFLAGS=$LDFLAGS

Installing https://luarocks.org/lua-cjson-2.1.0.6-1.src.rock

lua-cjson 2.1.0.6-1 depends on lua >= 5.1 (5.1-1 provided by VM)
clang -ggdb -fPIC -fsanitize=address -fsanitize=fuzzer-no-link -I/usr/include/lua5.1 -c lua_cjson.c -o lua_cjson.o
clang -ggdb -fPIC -fsanitize=address -fsanitize=fuzzer-no-link -I/usr/include/lua5.1 -c strbuf.c -o strbuf.o
clang -ggdb -fPIC -fsanitize=address -fsanitize=fuzzer-no-link -I/usr/include/lua5.1 -c fpconv.c -o fpconv.o
gcc -shared -o cjson.so lua_cjson.o strbuf.o fpconv.o
No existing manifest. Attempting to rebuild...
lua-cjson 2.1.0.6-1 is now installed in /home/sergeyb/sources/luzer/build/modules (license: MIT)
```

Create a file `luzer_example_json.lua` with a fuzzing target:

```lua
local luzer = require("luzer")
local json = require("cjson")

local function TestOneInput(buf)
    local text, err = pcall(json.decode, buf)
    if not err then
        local encoded = json.encode(text)
        assert(encoded == buf)
    end
end

luzer.Fuzz(TestOneInput)
```

Setup environment and execute the test:

```sh
$ eval $(luarocks path)
$ luajit luzer_example_json.lua
```

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

#### Visualizing Code Coverage

Examining which lines are executed is helpful for understanding
the effectiveness of your fuzzer. `luzer` is compatible with
[LuaCov][luacov-website]: you can run your fuzzer using the
LuaCov module as you would for any other Lua script. Here's an
example:

```sh
mkdir corpus_dir
lua examples/example_basic.lua -runs=1000 corpus_dir
luarocks install --local https://raw.githubusercontent.com/lunarmodules/luacov/refs/heads/master/luacov-scm-1.rockspec
eval $(luarocks path)
lua -lluacov examples/example_basic.lua -runs=1 corpus_dir/
luacov examples/example_basic.lua luacov.stats.out
cat luacov.report.out
==============================================================================
examples/example_basic.lua
==============================================================================
 2 local luzer = require("luzer")

   local function TestOneInput(buf)
*0     local fdp = luzer.FuzzedDataProvider(buf)
*0     local str = fdp:consume_string(4)

*0     local b = {}
*0     str:gsub(".", function(c) table.insert(b, c) end)
*0     local count = 0
*0     if b[1] == "o" then count = count + 1 end
*0     if b[2] == "o" then count = count + 1 end
*0     if b[3] == "p" then count = count + 1 end
*0     if b[4] == "s" then count = count + 1 end

*0     if count == 4 then assert(nil) end
   end

 2 local args = {
 2     only_ascii = 1,
 2     print_pcs = 1,
   }
 2 luzer.Fuzz(TestOneInput, nil, args)

==============================================================================
Summary
==============================================================================

File                       Hits Missed Coverage
-----------------------------------------------
examples/example_basic.lua 5    10     33.33%
-----------------------------------------------
Total                      5    10     33.33%
```

Beware, code coverage reports are only generated when option
`-runs=1` and a path to a non-empty directory with corpus are
specified. The option `-runs=1` is required because Lua debug hook
needed by LuaCov is also used for code instrumentation. In Lua
only one hook can be enabled at the same time, so we disable our
own hook for instrumentation when `-runs=1` is specified to allow
LuaCov work. The message "Lua debug hook is disabled" is printed,
when hook for Lua code instrumentation is disabled:

```
$ lua -lluacov examples/example_basic.lua -runs=1 corpus_dir/
INFO: Lua debug hook is disabled.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1369707749
INFO: Loaded 1 modules   (77 inline 8-bit counters): 77 [0x7ff92b371933, 0x7ff92b371980),
INFO: Loaded 1 PC tables (77 PCs): 77 [0x7ff92b371980,0x7ff92b371e50),
INFO:       10 files found in corpus_dir/
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: seed corpus: files: 10 min: 1b max: 8b total: 29b rss: 44Mb
#11     INITED cov: 24 ft: 56 corp: 9/27b exec/s: 0 rss: 44Mb
#11     DONE   cov: 24 ft: 56 corp: 9/27b lim: 8 exec/s: 0 rss: 44Mb
Done 11 runs in 0 second(s)
```

[ffi-library-url]: https://luajit.org/ext_ffi.html
[programming-in-lua-8]: https://www.lua.org/pil/8.html
[programming-in-lua-24]: https://www.lua.org/pil/24.html
[atheris-native-extensions]: https://github.com/google/atheris/blob/master/native_extension_fuzzing.md
[atheris-native-extensions-video]: https://www.youtube.com/watch?v=oM-7lt43-GA
[luacov-website]: https://lunarmodules.github.io/luacov/
