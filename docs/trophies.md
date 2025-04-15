## Trophies

`luzer` has found the following vulnerabilities and bugs.

If you find bugs with `luzer`, we would like to hear from you!
Feel free to open an issue or submit a pull request.

1. Segmentation fault on msgpack decoding,
   https://github.com/tarantool/tarantool/issues/7818
1. Wrong datetime calculation (A - A != B - B),
   https://github.com/tarantool/tarantool/issues/7144
1. Wrong datetime calculation (A - B + B != A),
   https://github.com/tarantool/tarantool/issues/7145
1. There is a difference of 1 sec with subtraction of the same datetimes,
   https://github.com/tarantool/tarantool/issues/6882
1. Tarantool encode decimal number with unsupported precision,
   https://github.com/tarantool/tarantool/issues/7112
1. SIGSEGV on parsing MessagePack buffer: `mp_check_uint: Assertion 'cur < end' failed`,
   https://github.com/tarantool/tarantool/issues/10360
1. SIGSEGV on parsing MessagePack buffer: `decimal_unpack: Assertion 'len > 0' failed`,
   https://github.com/tarantool/tarantool/issues/10361
1. Attempt to perform arithmetic on a nil value within `parser:parse()` call,
   https://github.com/manoelcampos/xml2lua/issues/106
1. Attempt to apply table method to string object within `parser:parse()` call,
   https://github.com/manoelcampos/xml2lua/issues/107
1. Attempt to index a `nil` value within `parser:parse()` call,
   https://github.com/manoelcampos/xml2lua/issues/108
