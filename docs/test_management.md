## Test management

luzer-based tests can be organized in two ways: as a standalone fuzz targets,
as shown in the Quickstart section, and integrated into the test framework.

### Using a test framework integration

To use fuzzing in your normal development workflow, a tight integration with
the Busted test framework is provided. This coupling allows the execution of
fuzz tests alongside your normal unit tests and seamlessly detect problems on
your local machine or in your CI, enabling you to check that found bugs stay
resolved forever.

Furthermore, the Busted integration enables great IDE support, so that
individual inputs can be run or even debugged, similar to what you would expect
from normal Busted tests.

A fuzz test in [Busted][busted-url] looks similar to the following example:

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

describe("arithmetic functions", function()
    it("sum of numbers", function()
        luzer.Fuzz(TestOneInput)
    end)
end)
```

To run the tests, execute the following command: `busted spec/sum_spec.lua`.

```sh
$ busted spec/sum_spec.lua
●
1 success / 0 failures / 0 errors / 0 pending : 0.001857 seconds
```

#### Using standalone fuzz targets

To use fuzzing in your normal development workflow, a tight integration with
the Busted test framework is provided. This coupling allows the execution of
fuzz tests alongside your normal unit tests and seamlessly detect problems on
your local machine or in your CI, enabling you to check that found bugs stay
resolved forever.

Create a fuzz target invoking your code:

```lua
local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(3)

    local b = {}
    str:gsub(".", function(c) table.insert(b, c) end)
    local count = 0
    if b[1] == "l" then count = count + 1 end
    if b[2] == "u" then count = count + 1 end
    if b[3] == "a" then count = count + 1 end

    if count == 3 then assert(nil) end
end

luzer.Fuzz(TestOneInput)
```

Start the fuzzer using the fuzz target:

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

[busted-url]: https://lunarmodules.github.io/busted/
