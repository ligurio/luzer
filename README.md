[![Static analysis](https://github.com/ligurio/luzer/actions/workflows/check.yaml/badge.svg)](https://github.com/ligurio/luzer/actions/workflows/check.yaml)
[![Testing](https://github.com/ligurio/luzer/actions/workflows/test.yaml/badge.svg)](https://github.com/ligurio/luzer/actions/workflows/test.yaml)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)

# luzer: A Coverage-Guided, Native Lua Fuzzer

luzer is a coverage-guided Lua fuzzing engine. It supports fuzzing of Lua code,
but also native extensions written for Lua. Luzer is based off of
[libFuzzer][libfuzzer-url]. When fuzzing native code, luzer can be used in
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

### API

- `LLVMFuzzerCustomMutator(data, size, max_size, seed)` - function that called
  for each mutation. Optional user-provided custom mutator. Mutates raw data in
  `[data, data+size)` inplace. Returns the new size, which is not greater than
  `max_size`. Given the same seed produces the same mutation.
- `LLVMFuzzerMutate(data, size, max_size)` - function that called for each
  mutation. libFuzzer-provided function to be used inside
  `LLVMFuzzerCustomMutator`. Mutates raw data in `[data, data+size)` inplace.
  Returns the new size, which is not greater than `max_size`.

## Fuzzing Lua programs

```lua
$ cat << EOF > sample.lua
local luzer = require("luzer")

local function TestOneInput(buf)
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

luzer.Setup({}, TestOneInput)
luzer.Fuzz()
EOF
$
```

```sh
$ luarocks install --tree modules --lua-version 5.3 lua-cmsgpack 0.4.0-0 CC="afl-gcc" CFLAGS="-ggdb -fPIC"
$ luarocks path
$ export LUA_PATH="$LUA_PATH;modules/lib/lua/5.3/?.lua"
$ export LUA_CPATH="$LUA_CPATH;modules/lib/lua/5.3/?.so"
```

### API

The luzer module provides two key functions: `Setup()` and `Fuzz()`.

- `Setup(args, test_one_input, internal_libfuzzer=None)`
  - `args`: A list of strings: the process arguments to pass to the fuzzer,
    typically sys.argv. This argument list may be modified in-place, to remove
    arguments consumed by the fuzzer. See the LibFuzzer docs for a list of such
    options. https://llvm.org/docs/LibFuzzer.html#options
  - `test_one_input`: your fuzzer's entry point. Must take a single bytes
    argument. This will be repeatedly invoked with a single bytes container.
  - `internal_libfuzzer`: Indicates whether libfuzzer will be provided by atheris
    or by an external library (see native_extension_fuzzing.md). If unspecified,
    luzer will determine this automatically. If fuzzing pure Lua, leave this
    as `true`.
- `Fuzz()` starts the fuzzer. You must have called `Setup()` before calling
  this function. This function does not return. In many cases `Setup()` and
  `Fuzz()` could be combined into a single function, but they are separated
  because you may want the fuzzer to consume the command-line arguments it
  handles before passing any remaining arguments to another setup function.
- `FuzzedDataProvider` Often, a `bytes` object is not convenient input to your
  code being fuzzed. Similar to libFuzzer, we provide a FuzzedDataProvider to
  translate these bytes into other input forms.

You can construct the `FuzzedDataProvider` with:

```lua
fdp = atheris.FuzzedDataProvider(input_bytes)
```

The `FuzzedDataProvider` then supports the following functions:

```lua
def ConsumeBytes(count: int)
```

Consume `count` bytes.

```lua
def ConsumeUnicode(count: int)
```

Consume unicode characters. Might contain surrogate pair characters, which
according to the specification are invalid in this situation. However, many
core software tools (e.g. Windows file paths) support them, so other software
often needs to too.

```lua
def ConsumeUnicodeNoSurrogates(count: int)
```

Consume unicode characters, but never generate surrogate pair characters.

```lua
def ConsumeString(count: int)
```

Alias for `ConsumeBytes` in Python 2, or `ConsumeUnicode` in Python 3.

```lua
def ConsumeInt(int: bytes)
```

Consume a signed integer of the specified size (when written in two's
complement notation).

```lua
def ConsumeUInt(int: bytes)
```

Consume an unsigned integer of the specified size.

```lua
def ConsumeIntInRange(min: int, max: int)
```

Consume an integer in the range [min, max].

```lua
def ConsumeIntList(count: int, bytes: int)
```

Consume a list of count integers of size bytes.

```lua
def ConsumeIntListInRange(count: int, min: int, max: int)
```

Consume a list of count integers in the range [`min`, `max`].

```lua
def ConsumeFloat()
```

Consume an arbitrary floating-point value. Might produce weird values like `NaN`
and `Inf`.

```lua
def ConsumeRegularFloat()
```

Consume an arbitrary numeric floating-point value; never produces a special
type like `NaN` or `Inf`.

```lua
def ConsumeProbability()
```

Consume a floating-point value in the range [0, 1].

```lua
def ConsumeFloatInRange(min: float, max: float)
```

Consume a floating-point value in the range [`min`, `max`].

```lua
def ConsumeFloatList(count: int)
```

Consume a list of count arbitrary floating-point values. Might produce weird
values like `NaN` and `Inf`.

```lua
def ConsumeRegularFloatList(count: int)
```

Consume a list of count arbitrary numeric floating-point values; never produces
special types like `NaN` or `Inf`.

```lua
def ConsumeProbabilityList(count: int)
```

Consume a list of count floats in the range [0, 1].

```lua
def ConsumeFloatListInRange(count: int, min: float, max: float)
```

Consume a list of count floats in the range [`min`, `max`]

```lua
def PickValueInList(l: list)
```

Given a list, pick a random value

```lua
def ConsumeBool()
```

Consume either `true` or `false`.

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

## TODO

- Promote:
  - https://groups.google.com/g/libfuzzer
  - https://github.com/uhub/awesome-lua
  - lobsters

[libfuzzer-url]: https://llvm.org/docs/LibFuzzer.html
[libfuzzer-mutators-url]: https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md
