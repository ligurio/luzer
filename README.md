[![Static analysis](https://github.com/ligurio/luzer/actions/workflows/check.yaml/badge.svg)](https://github.com/ligurio/luzer/actions/workflows/check.yaml)
[![Testing](https://github.com/ligurio/luzer/actions/workflows/test.yaml/badge.svg)](https://github.com/ligurio/luzer/actions/workflows/test.yaml)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)

# luzer: A Coverage-Guided, Native Lua Fuzzer

luzer is a coverage-guided Lua fuzzing engine. It supports fuzzing of Lua code,
but also native extensions written for Lua. Lua is based off of
[libFuzzer][libfuzzer-url]. When fuzzing native code, Lua can be used in
combination with Address Sanitizer or Undefined Behavior Sanitizer to catch
extra bugs.

## Installation

```sh
$ luarocks --local install luzer
```

## Using custom mutators

luzer allows [custom mutators][libfuzzer-mutators-url] to be written in Lua 5.1
(including Lua-JIT), 5.2, 5.3 or 5.4.

The environment variable `LIBFUZZER_CUSTOM_MUTATOR_LUA_SCRIPT` can be set to
the path to the Lua mutator script. The default path is
`./libfuzzer_mutator.lua`.

To run the Lua example, use

```sh
LIBFUZZER_CUSTOM_MUTATOR_LUA_SCRIPT=./libfuzzer_mutator.lua example_compressed
```

All you need to do on the C/C++ side is

```
#include "libfuzzer_mutator.cpp"
```

in the target file where you have `LLVMFuzzerTestOneInput` (or any other
compilation unit that is linked to the target) and then build with the Lua
include and linker flags added to your build configuration.

Then write a Lua script that does what you would like the fuzzer to do, you
might want to use the `libfuzzer_mutator.lua` script. The environment variable
`LIBFUZZER_CUSTOM_MUTATOR_LUA_SCRIPT` can be set to the path to the Lua mutator
script. The default path is `./libfuzzer_mutator.lua`. Then just run your fuzzing as
shown in the examples above.

API (see example: https://github.com/google/atheris):

- `LLVMFuzzerCustomMutator()`
- `LLVMFuzzerMutate()`

## Fuzzing Lua programs

```sh
$ cat << EOF > sample.lua
local function crash(buf)
    local b = {}
    buf:gsub(".", function(c) table.insert(b, c) end)
    if b[1] == 'c' then
        if b[2] == 'r' then
            if b[3] == 'a' then
                if b[4] == 's' then
                    if b[5] == 'h' then
                        assert(nil)
                    end
                end
            end
        end
    end
end
EOF
$
```

```sh
$ luarocks install --tree modules --lua-version 5.3 lua-cmsgpack 0.4.0-0 CC="afl-gcc" CFLAGS="-ggdb -fPIC"
$ luarocks path
$ export LUA_PATH="$LUA_PATH;modules/lib/lua/5.3/?.lua"
$ export LUA_CPATH="$LUA_CPATH;modules/lib/lua/5.3/?.so"
```

## Hacking

For developing `luzer` you need to install packages with libraries and headers
and CMake. On Debian: `apt install -y liblua5.1-0-dev libclang-common-14-dev
libstdc++-11-dev cmake`.

```sh
$ cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -S . -B build
$ cmake --build build --parallel
$ cmake --build build --target test
```

You are ready to make patches!

## License

Copyright © 2021-2022 [Sergey Bronnikov](https://bronevichok.ru/)

Distributed under the ISC License.

[libfuzzer-url]: https://llvm.org/docs/LibFuzzer.html
[libfuzzer-mutators-url]: https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md
