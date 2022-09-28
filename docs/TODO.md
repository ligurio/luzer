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
