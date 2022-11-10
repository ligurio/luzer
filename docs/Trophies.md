## Trophies


- [Confirmed] `./third_party/luajit/src/lj_debug.c:104: BCPos debug_framepc(lua_State *, GCfunc *, cTValue *): Assertion 'bc_isret( ((BCOp)((ins[-1])&0xff)))' failed.`
- [Confirmed] "Fix narrowing of unary minus"
  https://github.com/tarantool/tarantool/issues/6976
- [Confirmed] `Assertion 'ls->p < ls->pe' failed: lj_bcread.c:122: uint32_t bcread_byte(LexState *)`
  https://github.com/tarantool/tarantool/issues/4824
- [Fixed] "http\_parser() crashes (src/lib/http\_parser/http\_parser.h)"
  https://github.com/tarantool/security/issues/6
- [Fixed] "swim: fix out of bounds access in proto decode"
  https://github.com/tarantool/tarantool/pull/6614
- [Fixed] "swim: fix debug assertion abort in proto decode"
  https://github.com/tarantool/tarantool/pull/6662
- [Fixed] "app: query parameters parsing is slow under ASAN"
  https://github.com/tarantool/tarantool/issues/7155
- [Confirmed] "Segmentation fault on msgpack decoding"
  https://github.com/tarantool/tarantool/issues/7818 (found by luzer)
- [Confirmed] "Wrong datetime calculation (A - B + B != A)"
  https://github.com/tarantool/tarantool/issues/7145 (found by luzer)
- [Fixed] "There is a difference of 1 sec with subtraction of the same datetimes"
  https://github.com/tarantool/tarantool/issues/6882 (found by luzer)
- [Confirmed] "Tarantool encode decimal number with unsupported precision"
  https://github.com/tarantool/tarantool/issues/7112 (found by luzer)
