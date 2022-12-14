# Structure-Aware Fuzzing

LGen - the Lua Language Generator is a sentence (test data) generator based on
syntax description and which uses coverage criteria to restrict the set of
generated sentences. This generator takes as input a grammar described in a
notation based on Extended BNF (EBNF) and returns a set of sentences of the
language corresponding to this grammar.

- URL: https://bitbucket.org/chentz/lgen/src/master/
- URL: https://bitbucket.org/chentz/lgen/src/master/GenerationEngine/Grammars/
- URL: http://lgen.wikidot.com/repgrammar

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

## References

- [libFuzzer Tutorial][libfuzzer-tutorial-url]
- [How To Split A Fuzzer-Generated Input Into Several ][split-inputs-url]

<!--

`libprotobuf-mutator` is a library to randomly mutate protobuffers.
It could be used together with guided fuzzing engines, such as libFuzzer.
Requires protobuf and LPM support in Lua.
- URL: https://github.com/google/libprotobuf-mutator

ProtoBuf implementations:

- sproto - yet another protocol library like google protocol buffers , but
  simple and fast. https://github.com/cloudwu/sproto
- pbc - a protocol buffers library for C,
  https://github.com/cloudwu/pbc
- μpb - a small protobuf implementation in C,
  https://github.com/haberman/upb
- Google's Protocol Buffers project, ported to Lua,
  https://github.com/sean-lin/protoc-gen-lua
- lua-protobuf provides a Lua interface to Google's Protocol Buffers.
  https://github.com/indygreg/lua-protobuf
- C module for Lua manipulating Google's protobuf protocol, both for version 2
  and 3 syntax and semantics.
  https://github.com/starwing/lua-protobuf
- Python https://blog.trailofbits.com/2016/05/18/protofuzz-a-protobuf-fuzzer/
-->
