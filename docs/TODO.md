### TODO:

- падает когда args == {}
- починить проблему с первым аргументом в opts
- тесты для `custom_mutator()`

- трейсинг для `LUA_LINE`, `LUA_CALL`
- добавить `fdp:oneof()` для выбора случайного элемента в таблице
- FDP: https://hypothesis.readthedocs.io/en/latest/data.html
- https://github.com/google/centipede/tree/main/puzzles
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

- использование с mod_lua
	https://httpd.apache.org/docs/trunk/developer/lua.html
	https://httpd.apache.org/docs/trunk/mod/mod_lua.html
- таргеты или воспроизвести с помощью luzer:
	https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce
	https://github.com/vulhub/vulhub/tree/master/redis/CVE-2022-0543
	https://nvd.nist.gov/vuln/detail/CVE-2020-36309
	https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=Lua
	https://en.m.wikipedia.org/wiki/List_of_applications_using_Lua
		Bodemcu
		Darktable
		Haproxy
		Lightroom
		lua-openssl
		Neovim
		NetBSD lua
		Nmap
		OpenResty
		Pandoc
		PowerDNS
		prosody
		Prosody
		Redis
		Snort
		Torch
		Varnish
		Vlc
		Wireshark
		Zerobrane

- патч для Lua с поддержкой трейсинга
- IJON
- описать в доке составление словаря с помощью mulua, https://github.com/RUB-SysSec/ijon/tree/master/libtokencap
- ? втащить исходный код libfuzzer в luzer
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

## Promote:

- https://groups.google.com/g/libfuzzer
- https://github.com/uhub/awesome-lua
- lobsters
- группа в телеграме про фаззинг для ФСТЭК
- ZeroBrane Studio?
- opennet https://www.opennet.ru/opennews/art.shtml?num=54204
- https://www.reddit.com/r/fuzzing/
- https://www.reddit.com/r/lua/
