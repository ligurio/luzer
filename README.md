[![Static analysis](https://github.com/ligurio/luzer/actions/workflows/check.yaml/badge.svg)](https://github.com/ligurio/luzer/actions/workflows/check.yaml)
[![Testing](https://github.com/ligurio/luzer/actions/workflows/test.yaml/badge.svg)](https://github.com/ligurio/luzer/actions/workflows/test.yaml)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)

# luzer

a coverage-guided, native Lua fuzzer.

## Overview

Fuzzing is a type of automated testing which continuously manipulates inputs to
a program to find bugs. `luzer` uses coverage guidance to intelligently walk
through the code being fuzzed to find and report failures to the user. Since it
can reach edge cases which humans often miss, fuzz testing can be particularly
valuable for finding security exploits and vulnerabilities.

`luzer` is a coverage-guided Lua fuzzing engine. It supports fuzzing of Lua
code, but also C extensions written for Lua. Luzer is based off of
[libFuzzer][libfuzzer-url]. When fuzzing native code, `luzer` can be used in
combination with Address Sanitizer or Undefined Behavior Sanitizer to catch
extra bugs.

## Installation

```sh
$ luarocks --local install luzer
```

## Writing fuzz tests in Lua

- There must be exactly one fuzz target per fuzz test.
- Fuzz targets should be fast and deterministic so the fuzzing engine can work
  efficiently, and new failures and code coverage can be easily reproduced.
- Since the fuzz target is invoked in parallel across multiple workers and in
  nondeterministic order, the state of a fuzz target should not persist past
  the end of each call, and the behavior of a fuzz target should not depend on
  global state.

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

While fuzzing is in progress, the fuzzing engine generates new inputs and runs
them against the provided fuzz target. By default, it continues to run until a
failing input is found, or the user cancels the process (e.g. with Ctrl^C).

The output will look something like this:

```
~ go test -fuzz FuzzFoo
fuzz: elapsed: 0s, gathering baseline coverage: 0/192 completed
fuzz: elapsed: 0s, gathering baseline coverage: 192/192 completed, now fuzzing with 8 workers
fuzz: elapsed: 3s, execs: 325017 (108336/sec), new interesting: 11 (total: 202)
fuzz: elapsed: 6s, execs: 680218 (118402/sec), new interesting: 12 (total: 203)
fuzz: elapsed: 9s, execs: 1039901 (119895/sec), new interesting: 19 (total: 210)
fuzz: elapsed: 12s, execs: 1386684 (115594/sec), new interesting: 21 (total: 212)
PASS
ok      foo 12.692s
```

The first lines indicate that the "baseline coverage" is gathered before
fuzzing begins.

To gather baseline coverage, the fuzzing engine executes both the seed corpus
and the generated corpus, to ensure that no errors occurred and to understand
the code coverage the existing corpus already provides.

<!--
TODO: https://go.dev/doc/fuzz/

```sh
$ luarocks install --tree modules --lua-version 5.1 lua-cmsgpack CC="clang" CFLAGS="-g -fsanitize=fuzzer-no-link,address"
$ luarocks path
$ export LUA_PATH="$LUA_PATH;modules/lib/lua/5.1/?.lua"
$ export LUA_CPATH="$LUA_CPATH;modules/lib/lua/5.1/?.so"
$ cat test.lua
local luzer = require("luzer")

local function TestOneInput(buf)
    local b = {}
    buf:gsub(".", function(c) table.insert(b, c) end)
    -- FIXME
end

luzer.Setup({}, TestOneInput)
luzer.Fuzz()
$ luajit test.lua
```
-->

## Fuzzing API

The luzer module provides two key functions: `Setup()` and `Fuzz()`.

`Setup(args, test_one_input, internal_libfuzzer=None)`
- `args`: A list of strings: the process arguments to pass to the fuzzer,
  typically `argv`. This argument list may be modified in-place, to remove
  arguments consumed by the fuzzer. See the [libFuzzer docs][libfuzzer-options-url]
  for a list of such options.
- `test_one_input`: Your fuzzer's entry point. Must take a single bytes
  argument. This will be repeatedly invoked with a single bytes container.
- `internal_libfuzzer`: Indicates whether libfuzzer will be provided by
  luzer or by an external library. If unspecified, luzer will determine
  this automatically.

`require_instrument` is a function that imports Lua module in the same way as
the standard function `require`, but adds module's functions to whitelist used
for gathering code coverage.

`Fuzz()` starts the fuzzer. You must have called `Setup()` before calling this
function. This function does not return. In many cases `Setup()` and `Fuzz()`
could be combined into a single function, but they are separated because you
may want the fuzzer to consume the command-line arguments it handles before
passing any remaining arguments to another setup function.

Often, a `bytes` object is not convenient input to your code being fuzzed.
Similar to libFuzzer, luzer provides a `FuzzedDataProvider` that can simplify the
task of creating a fuzz target by translating the raw input bytes received from
the fuzzer into useful primitive Lua types.

You can construct the `FuzzedDataProvider` with:

```lua
local fdp = luzer.FuzzedDataProvider(input_bytes)
```

The `FuzzedDataProvider` then supports the following functions:

- `consume_string(min, max)` - consume a string with length in the range `[min,
  max]`.
- `consume_strings(min, max, count)` - consume a list of `count` strings with
  length in the range `[min, max]`.
- `consume_integer(min, max)` - consume a signed integer with size in the range
  `[min, max]`.
- `consume_integers(min, max, count)` - consume a list of `count` integers in the
  range `[min, max]`.
- `consume_number(min, float)` - consume a floating-point value in the range
  `[min, max]`.
- `consume_numbers(min, max, count)` - consume a list of `count` floats in the
  range `[min, max]`.
- `consume_boolean()` - consume either `true` or `false`.
- `consume_booleans(count)` - consume a list of `count` booleans.
- `consume_probability()` - consume a floating-point value in the range `[0, 1]`.
- `remaining_bytes()` - returns the number of unconsumed bytes in the fuzzer
  input.
- `pick_value_in_table()` - given a table, pick a random value.

## Using Lua custom mutators

`luzer` allows [custom mutators][libfuzzer-mutators-url] to be written in Lua 5.1
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

## Custom mutator API

- `LLVMFuzzerCustomMutator(data, size, max_size, seed)` - function that called
  for each mutation. Optional user-provided custom mutator. Mutates raw data in
  `[data, data+size)` inplace. Returns the new size, which is not greater than
  `max_size`. Given the same seed produces the same mutation.
- `LLVMFuzzerMutate(data, size, max_size)` - function that called for each
  mutation. libFuzzer-provided function to be used inside
  `LLVMFuzzerCustomMutator`. Mutates raw data in `[data, data+size)` inplace.
  Returns the new size, which is not greater than `max_size`.

<!--
## Companion tools

Testing could be more rigorous with using these tools:

- `Lua` https://github.com/fab13n/checks
- `Lua` https://github.com/tarantool/checks
- `Lua` https://github.com/luc-tielen/lua-quickcheck
- `C/C++` Address Sanitizer
- `C/C++` Memory Sanitizer
- `C/C++` Undefined Behavior Sanitizer
- `C/C++` Thread Sanitizer
-->

## License

Copyright © 2021-2022 [Sergey Bronnikov][bronevichok-url].

Distributed under the ISC License.

<!--
## TODO

- Promote:
  - https://groups.google.com/g/libfuzzer
  - https://github.com/uhub/awesome-lua
  - lobsters
  - группа в телеграме про фаззинг для ФСТЭК
  - ZeroBrane Studio?
-->

[libfuzzer-url]: https://llvm.org/docs/LibFuzzer.html
[libfuzzer-options-url]: https://llvm.org/docs/LibFuzzer.html#options
[libfuzzer-mutators-url]: https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md
[bronevichok-url]: https://bronevichok.ru/
