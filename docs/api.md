## API

### Fuzzing functions

The `luzer` module provides a function `Fuzz()`.

`Fuzz(test_one_input, [custom_mutator, [args]])` starts the fuzzer.
This function does not return.

Function accepts following arguments:

- `test_one_input` is a fuzzer's entry point (equivalent to `LLVMFuzzerTestOneInput`), it
  is a function that must take a single string argument. This will be repeatedly
  invoked with a single string container.
- `custom_mutator` (optional) defines a custom mutator function
  (equivalent to `LLVMFuzzerCustomMutator`). Default is `nil`.
- `args` (optional) is a table with arguments: the process arguments to pass to the
  fuzzer. Field `corpus` specifies a path to a directory with seed corpus, see a
  list with other options in the [libFuzzer documentation][libfuzzer-options-url].
  Default is an empty table.

It may be desirable to reject some inputs, i.e. to not add them to the corpus.
For example, when fuzzing an API consisting of parsing and other logic, one may
want to allow only those inputs into the corpus that parse successfully. If the
fuzz target returns `-1` on a given input, `luzer` will not add that input top
the corpus, regardless of what coverage it triggers.

### Structure-Aware Fuzzing

`luzer` is based on a coverage-guided mutation-based fuzzer (LibFuzzer). It has
the advantage of not requiring any grammar definition for generating inputs,
making its setup easier. The disadvantage is that it will be harder for the
fuzzer to generate inputs for code that parses complex data types. Often the
inputs will be rejected early, resulting in low coverage. For solving this
issue `luzer` offers `FuzzedDataProvider` and two functions to customize the
mutation strategy which is especially useful when fuzzing functions that
require structured input.

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
- `consume_strings(max_length, count)` - consume a table with `count` strings with
  length in the range `[0, max_length]`.
- `consume_integer(min, max)` - consume a signed integer with size in the range
  `[min, max]`.
- `consume_integers(min, max, count)` - consume a table of `count` integers in the
  range `[min, max]`.
- `consume_number(min, max)` - consume a floating-point value in the range
  `[min, max]`.
- `consume_numbers(min, max, count)` - consume a table of `count` floats in the
  range `[min, max]`. If there's no input data left, returns `min`. Note that
  `min` must be less than or equal to `max`.
- `consume_boolean()` - consume either `true` or `false`, or `false` when no
  data remains.
- `consume_booleans(count)` - consume a table of `count` booleans.
- `consume_probability()` - consume a floating-point value in the range `[0, 1]`.
  If there's no input data left, always returns 0.
- `remaining_bytes()` - returns the number of unconsumed bytes in the fuzzer
  input.
- `oneof()` - returns a random element in the specified Lua array. With empty
  table `oneof()` returns a `nil` value.

Examples:

```lua
> luzer = require("luzer")
> fdp = luzer.FuzzedDataProvider(string.rep("A", 10^9))
> fdp:consume_boolean()
true
> fdp:consume_string(2, 10)
AAAAAAAAA
```

Learn more about grammar-based fuzzing in the
[documentation](grammar_based_fuzzing.md).

[libfuzzer-options-url]: https://llvm.org/docs/LibFuzzer.html#options
