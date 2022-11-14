### TODO:

- падает когда args == {}
- починить проблему с первым аргументом в opts
- тесты для custom_mutator()
- трейсинг

- коллбек-функция которая вызывается каждый раз когда появляются новые результаты от фаззера
	результаты получать парсингом вывода libfuzzer
	поток вывода получать через dup()
	https://github.com/tarantool/luatest/blob/master/luatest/capture.lua
- рисовать графики статуса фаззинга
	https://gitlab.com/hansonry/luasvgwriter
	https://github.com/Jericho1060/svg-lua
- фаззинг нативных модулей
	- шарить фидбек от C кода и Lua кода (custom coverage functions https://clang.llvm.org/docs/SanitizerCoverage.html)
	- ASAN LD_PRELOAD
	- /usr/lib/llvm-13/lib/clang/13.0.1/lib/linux/libclang_rt.ubsan_standalone-x86_64.so
	- /usr/lib/llvm-13/lib/clang/13.0.1/lib/linux/libclang_rt.asan-x86_64.so
	- https://github.com/google/sanitizers/wiki/SanitizerCommonFlags
	- https://github.com/google/sanitizers/wiki/AddressSanitizerAsDso#asan-and-ld_preload

- патч для Lua с поддержкой трейсинга
- IJON
- описать в доке составление словаря с помощью mulua, https://github.com/RUB-SysSec/ijon/tree/master/libtokencap
- ? втащить исходный код libfuzzer в luzer
- добавить `oneof()` для выбора случайного элемента в таблице
- `consume_byte()` https://github.com/luc-tielen/lua-quickcheck/blob/master/lqc/generators/byte.lua
- `consume_char()` https://github.com/luc-tielen/lua-quickcheck/blob/master/lqc/generators/char.lua
- `consume_string()` для Unicode, 6.5 – UTF-8 Support, https://www.lua.org/manual/5.4/manual.html
- поддержка luacov
  - https://github.com/lunarmodules/luacov/blob/master/src/luacov/runner.lua#L102-L117
  - https://lunarmodules.github.io/luacov/doc/modules/luacov.runner.html#debug_hook
- передавать корпус в таблице
- передавать словарь в таблице
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

## Promote:

- https://groups.google.com/g/libfuzzer
- https://github.com/uhub/awesome-lua
- lobsters
- группа в телеграме про фаззинг для ФСТЭК
- ZeroBrane Studio?
- opennet https://www.opennet.ru/opennews/art.shtml?num=54204
- https://www.reddit.com/r/fuzzing/
- https://www.reddit.com/r/lua/
