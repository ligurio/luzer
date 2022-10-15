### TODO:

- падает когда args == {}
- тесты для custom_mutator()
- трейсинг

- патч для Lua с поддержкой трейсинга
- генерировать словарь автоматически для более эффективного фаззинга
- добавить `oneof()` для выбора случайного элемента в таблице
- `consume_byte()` https://github.com/luc-tielen/lua-quickcheck/blob/master/lqc/generators/byte.lua
- `consume_char()` https://github.com/luc-tielen/lua-quickcheck/blob/master/lqc/generators/char.lua
- `consume_string()` для Unicode, 6.5 – UTF-8 Support, https://www.lua.org/manual/5.4/manual.html
- поддержка luacov
  - https://github.com/lunarmodules/luacov/blob/master/src/luacov/runner.lua#L102-L117
  - https://lunarmodules.github.io/luacov/doc/modules/luacov.runner.html#debug_hook
- передавать корпус в таблице
- передавать словарь в таблице
- интеграция с LPM
- генератор таблиц по схеме JSONschema https://github.com/jdesgats/ljsonschema
- общие свойства на основе Lua метатаблиц - https://github.com/luc-tielen/lua-quickcheck/issues/33
- автоматически генерировать тесты для Си (cparser)
- автоматически генерировать тесты для Lua (mulua?)

# tracing

https://clang.llvm.org/docs/SanitizerCoverage.html

With `-fsanitize-coverage=trace-pc-guard` the compiler will insert the
following code on every edge:

`__sanitizer_cov_trace_pc_guard(&guard_variable)`

With `-fsanitize-coverage=trace-cmp` the compiler will insert extra
instrumentation around comparison instructions.

// Called before a comparison instruction.
// Arg1 and Arg2 are arguments of the comparison.
`void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2);`
`void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2);`
`void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2);`
`void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2);`

// Called before a comparison instruction if exactly one of the arguments is constant.
// Arg1 and Arg2 are arguments of the comparison, Arg1 is a compile-time constant.
`void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2);`
`void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2);`
`void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2);`
`void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2);`

With `-fsanitize-coverage=trace-div` the compiler will instrument
integer division instructions (to capture the right argument of division).

// Called before a division statement.
// Val is the second argument of division.
`void __sanitizer_cov_trace_div4(uint32_t Val);`
`void __sanitizer_cov_trace_div8(uint64_t Val);`

With `-fsanitize-coverage=trace-gep` – the LLVM GEP instructions (to capture
array indices).

// Called before a GetElemementPtr (GEP) instruction
// for every non-constant array index.
`void __sanitizer_cov_trace_gep(uintptr_t Idx);`

With `-fsanitize-coverage=trace-loads` the compiler will instrument loads.

// Called before a load of appropriate size. Addr is the address of the load.
`void __sanitizer_cov_load1(uint8_t *addr);`
`void __sanitizer_cov_load2(uint16_t *addr);`
`void __sanitizer_cov_load4(uint32_t *addr);`
`void __sanitizer_cov_load8(uint64_t *addr);`
`void __sanitizer_cov_load16(__int128 *addr);`

With `-fsanitize-coverage=trace-stores` the compiler will instrument stores.

// Called before a store of appropriate size. Addr is the address of the store.
`void __sanitizer_cov_store1(uint8_t *addr);`
`void __sanitizer_cov_store2(uint16_t *addr);`
`void __sanitizer_cov_store4(uint32_t *addr);`
`void __sanitizer_cov_store8(uint64_t *addr);`
`void __sanitizer_cov_store16(__int128 *addr);`

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
