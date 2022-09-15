[![Static analysis](https://github.com/ligurio/luzer/actions/workflows/check.yaml/badge.svg)](https://github.com/ligurio/luzer/actions/workflows/check.yaml)
[![Testing](https://github.com/ligurio/luzer/actions/workflows/test.yaml/badge.svg)](https://github.com/ligurio/luzer/actions/workflows/test.yaml)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Luarocks](https://img.shields.io/luarocks/v/ligurio/luzer/scm-1)](https://luarocks.org/modules/ligurio/luzer)

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

## Writing Fuzz Tests In Lua

- There must be exactly one fuzz target per fuzz test.
- Fuzz targets should be fast and deterministic so the fuzzing engine can work
  efficiently, and new failures and code coverage can be easily reproduced.
- Since the fuzz target is invoked in parallel across multiple workers and in
  nondeterministic order, the state of a fuzz target should not persist past
  the end of each call, and the behavior of a fuzz target should not depend on
  global state.

```lua
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
```

While fuzzing is in progress, the fuzzing engine generates new inputs and runs
them against the provided fuzz target. By default, it continues to run until a
failing input is found, or the user cancels the process (e.g. with `Ctrl^C`).

The output will look something like this:

```
$ luajit examples/luzer_example.lua
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1557779137
INFO: Loaded 1 modules   (151 inline 8-bit counters): 151 [0x7f0640e706e3, 0x7f0640e7077a),
INFO: Loaded 1 PC tables (151 PCs): 151 [0x7f0640e70780,0x7f0640e710f0),
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED cov: 17 ft: 18 corp: 1/1b exec/s: 0 rss: 26Mb
#32	NEW    cov: 17 ft: 24 corp: 2/4b lim: 4 exec/s: 0 rss: 26Mb L: 3/3 MS: 5 ShuffleBytes-ShuffleBytes-CopyPart-ChangeByte-CMP- DE: "\x00\x00"-
...
```

The first lines indicate that the "baseline coverage" is gathered before
fuzzing begins.

To gather baseline coverage, the fuzzing engine executes both the seed corpus
and the generated corpus, to ensure that no errors occurred and to understand
the code coverage the existing corpus already provides.

**Fuzzing API**

The luzer module provides two key functions: `Setup()` and `Fuzz()`.

`Setup(args, test_one_input, custom_mutator)`
- `args`: A list of strings: the process arguments to pass to the fuzzer,
  typically `arg`. This argument list may be modified in-place, to remove
  arguments consumed by the fuzzer. See the [libFuzzer docs][libfuzzer-options-url]
  for a list of such options.
- `test_one_input`: Your fuzzer's entry point. Must take a single bytes
  argument. This will be repeatedly invoked with a single bytes container.
- `custom_mutator`: Define a custom mutator function (equivalent to
  `LLVMFuzzerCustomMutator`). Default is `nil`.

`require_instrument` imports Lua module in the same way as the standard
function `require`, but adds module's functions to whitelist used for gathering
code coverage.

`Fuzz()` starts the fuzzer. You must have called `Setup()` before calling this
function. This function does not return. In many cases `Setup()` and `Fuzz()`
could be combined into a single function, but they are separated because you
may want the fuzzer to consume the command-line arguments it handles before
passing any remaining arguments to another setup function.

It may be desirable to reject some inputs, i.e. to not add them to the corpus.
For example, when fuzzing an API consisting of parsing and other logic, one may
want to allow only those inputs into the corpus that parse successfully.

If the fuzz target returns `-1` on a given input, `luzer` will not add that
input top the corpus, regardless of what coverage it triggers.

**Structure-Aware Fuzzing**

Often, a `bytes` object is not convenient input to your code being fuzzed.
Similar to libFuzzer, luzer provides a `FuzzedDataProvider` that can simplify the
task of creating a fuzz target by translating the raw input bytes received from
the fuzzer into useful primitive Lua types.

You can construct the `FuzzedDataProvider` with:

```lua
local fdp = luzer.FuzzedDataProvider(input_bytes)
```

The `FuzzedDataProvider` then supports the following functions:

- `consume_string(max_length)` - consume a string with length in the range `[0,
  max_length]`. When it runs out of input data, returns what remains of the input.
- `consume_strings(max_length, count)` - consume a list of `count` strings with
  length in the range `[0, max_length]`.
- `consume_integer(min, max)` - consume a signed integer with size in the range
  `[min, max]`.
- `consume_integers(min, max, count)` - consume a list of `count` integers in the
  range `[min, max]`.
- `consume_number(min, max)` - consume a floating-point value in the range
  `[min, max]`.
- `consume_numbers(min, max, count)` - consume a list of `count` floats in the
  range `[min, max]`. If there's no input data left, returns `min`. Note that
  `min` must be less than or equal to `max`.
- `consume_boolean()` - consume either `true` or `false`, or `false` when no
  data remains.
- `consume_booleans(count)` - consume a list of `count` booleans.
- `consume_probability()` - consume a floating-point value in the range `[0, 1]`.
  If there's no input data left, always returns 0.
- `remaining_bytes()` - returns the number of unconsumed bytes in the fuzzer
  input.

Examples:

```lua
> luzer = require("luzer")
> fdp = luzer.FuzzedDataProvider(string.rep("A", 10^9))
> fdp.consume_boolean()
true
> fdp.consume_string(2, 10)
AAAAAAAAA
```

Learn more about fuzzing with libFuzzer and structure-aware fuzzing using
`FuzzedDataProvider`:

- [libFuzzer Tutorial][libfuzzer-tutorial-url]
- [How To Split A Fuzzer-Generated Input Into Several ][split-inputs-url]

## Using Custom Mutators Written In Lua

`luzer` allows [custom mutators][libfuzzer-mutators-url] to be written in Lua 5.1
(including Lua-JIT), 5.2, 5.3 or 5.4.

The environment variable `LIBFUZZER_CUSTOM_MUTATOR_LUA_SCRIPT` can be set to
the path to the Lua mutator script. The default path is
`./mutator.lua`.

To run the Lua example, use

```sh
LIBFUZZER_CUSTOM_MUTATOR_LUA_SCRIPT=./mutator.lua example_compressed
```

All you need to do on the C/C++ side is

```
#include "mutator.cpp"
```

in the target file where you have `LLVMFuzzerTestOneInput` (or any other
compilation unit that is linked to the target) and then build with the Lua
include and linker flags added to your build configuration.

Then write a Lua script that does what you would like the fuzzer to do, you
might want to use the `mutator.lua` script. The environment variable
`LIBFUZZER_CUSTOM_MUTATOR_LUA_SCRIPT` can be set to the path to the Lua mutator
script. The default path is `./mutator.lua`. Then just run your fuzzing as
shown in the examples above.

**Custom mutator API**

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

## Promote:

- https://groups.google.com/g/libfuzzer
- https://github.com/uhub/awesome-lua
- lobsters
- группа в телеграме про фаззинг для ФСТЭК
- ZeroBrane Studio?
- opennet https://www.opennet.ru/opennews/art.shtml?num=54204
- https://www.reddit.com/r/fuzzing/
-->

## License

Copyright © 2021-2022 [Sergey Bronnikov][bronevichok-url].

Distributed under the ISC License.

[libfuzzer-url]: https://llvm.org/docs/LibFuzzer.html
[libfuzzer-options-url]: https://llvm.org/docs/LibFuzzer.html#options
[libfuzzer-mutators-url]: https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md
[libfuzzer-tutorial-url]: https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md
[split-inputs-url]: https://github.com/google/fuzzing/blob/master/docs/split-inputs.md
[bronevichok-url]: https://bronevichok.ru/
