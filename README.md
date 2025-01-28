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

## Quickstart

To use luzer in your own project follow these few simple steps:

1. Setup `luzer` module:

```sh
$ luarocks --local install luzer
$ eval $(luarocks path)
```

2. Create a fuzz target invoking your code:

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

luzer.Fuzz(TestOneInput, nil, {})
```

3. Start the fuzzer using the fuzz target

```
$ luajit examples/example_basic.lua
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

While fuzzing is in progress, the fuzzing engine generates new inputs and runs
them against the provided fuzz target. By default, it continues to run until a
failing input is found, or the user cancels the process (e.g. with `Ctrl^C`).

The first lines indicate that the "baseline coverage" is gathered before
fuzzing begins.

To gather baseline coverage, the fuzzing engine executes both the seed corpus
and the generated corpus, to ensure that no errors occurred and to understand
the code coverage the existing corpus already provides.

See tests that uses luzer library in:

- Tarantool Lua API tests, https://github.com/ligurio/tarantool-lua-api-tests
- Lua standard library tests, https://github.com/ligurio/lua-stdlib-tests
- https://github.com/ligurio/snippets/tree/master/luzer-tests

## Documentation

See [documentation](docs/index.md).

## License

Copyright © 2022-2023 [Sergey Bronnikov][bronevichok-url].

Distributed under the ISC License.

[libfuzzer-url]: https://llvm.org/docs/LibFuzzer.html
[bronevichok-url]: https://bronevichok.ru/
