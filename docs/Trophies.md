## luzer

- "Segmentation fault on msgpack decoding"
  https://github.com/tarantool/tarantool/issues/7818
- "Wrong datetime calculation (A - B + B != A)"
  https://github.com/tarantool/tarantool/issues/7145
- [Fixed] "There is a difference of 1 sec with subtraction of the same datetimes"
  https://github.com/tarantool/tarantool/issues/6882
- "Tarantool encode decimal number with unsupported precision"
  https://github.com/tarantool/tarantool/issues/7112

## libFuzzer

- "Assertion `ls->p < ls->pe' failed: lj_bcread.c:122: uint32_t bcread_byte(LexState *)"
  https://github.com/tarantool/tarantool/issues/4824
- [Fixed] "http_parser() crashes (src/lib/http_parser/http_parser.h)"
  https://github.com/tarantool/security/issues/6
- [Fixed] "swim: fix out of bounds access in proto decode"
  https://github.com/tarantool/tarantool/pull/6614
- [Fixed] "swim: fix debug assertion abort in proto decode"
  https://github.com/tarantool/tarantool/pull/6662
- [Fixed] "app: query parameters parsing is slow under ASAN"
  https://github.com/tarantool/tarantool/issues/7155
