## Grammar-Based Fuzzing

There is no anything special for grammar-based fuzzing in `luzer`. Projects
listed below could help with generating grammar-aware inputs.

### LGen

LGen - the Lua Language Generator is a sentence (test data) generator based on
syntax description and which uses coverage criteria to restrict the set of
generated sentences. This generator takes as input a grammar described in a
notation based on Extended BNF (EBNF) and returns a set of sentences of the
language corresponding to this grammar.

- URL: https://bitbucket.org/chentz/lgen/src/master/
- URL: https://bitbucket.org/chentz/lgen/src/master/GenerationEngine/Grammars/
- URL: http://lgen.wikidot.com/repgrammar

### LPeg

The `re` module supports a somewhat conventional regex syntax for pattern usage
within LPeg.

- URL: http://www.inf.puc-rio.br/~roberto/lpeg/re.html

A Lua parser generator that makes it possible to describe grammars in a PEG
syntax. The tool will parse a given input using a provided grammar and if the
matching is successful produce an AST as an output with the captured values
using Lpeg. If the matching fails, labelled errors can be used in the grammar
to indicate failure position, and recovery grammars are generated to continue
parsing the input using LpegLabel. The tool can also automatically generate
error labels and recovery grammars for LL(1) grammars.
URL: https://github.com/vsbenas/parser-gen

Parsing common data formats via LPeg (e-mail, JSON, IPv4 and IPv6 addresses,
INI, strftime, URL).

- URL: https://github.com/spc476/LPeg-Parsers
- URL: https://github.com/daurnimator/lpeg_patterns

### References

- [libFuzzer Tutorial][libfuzzer-tutorial-url]
- [How To Split A Fuzzer-Generated Input Into Several ][split-inputs-url]

[libfuzzer-tutorial-url]: https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md
[split-inputs-url]: https://github.com/google/fuzzing/blob/master/docs/split-inputs.md
