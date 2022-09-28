### TODO:

- тесты для custom_mutator()
- трейсинг
- передавать опции командной строки для libfuzzer в таблице

- добавить `oneof()` для выбора случайного элемента в таблице
- `consume_byte()` https://github.com/luc-tielen/lua-quickcheck/blob/master/lqc/generators/byte.lua
- `consume_char()` https://github.com/luc-tielen/lua-quickcheck/blob/master/lqc/generators/char.lua
- `consume_string()` для Unicode, 6.5 – UTF-8 Support, https://www.lua.org/manual/5.4/manual.html
- поддержка luacov
  - https://github.com/lunarmodules/luacov/blob/master/src/luacov/runner.lua#L102-L117
  - https://lunarmodules.github.io/luacov/doc/modules/luacov.runner.html#debug_hook
- передавать корпус в таблице
- передавать словарь в таблице
- Structure-aware fuzzing with grammar
- генератор таблиц по схеме JSONschema https://github.com/jdesgats/ljsonschema
- общие свойства на основе Lua метатаблиц - https://github.com/luc-tielen/lua-quickcheck/issues/33
- автоматически генерировать тесты для Си
- автоматически генерировать тесты для Lua

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
