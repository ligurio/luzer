### TODO:

- совместимость с Lua 5.2 починить https://github.com/antirez/lua-cmsgpack/commit/2ed313c217218ebad01a6dd0aeca9eabac7e5cea
- починить проблему с первым аргументом в opts
- отладить `custom_mutator()`
- см https://github.com/geoffleyland/luatrace
- fix crash with malloc

-------------------------------

- патч для PUC Rio Lua с поддержкой трейсинга
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

- таргеты или воспроизвести с помощью luzer:
	https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce
	https://github.com/vulhub/vulhub/tree/master/redis/CVE-2022-0543
	https://nvd.nist.gov/vuln/detail/CVE-2020-36309
	https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=Lua
	https://en.m.wikipedia.org/wiki/List_of_applications_using_Lua
		? ScummVM https://github.com/scummvm/scummvm/blob/master/engines/grim/lua_v1_set.cpp
		https://github.com/openresty/lua-nginx-module
		openwrt's luci https://github.com/openwrt/luci
		Apache mod_lua
			https://httpd.apache.org/docs/trunk/developer/lua.html
			https://httpd.apache.org/docs/trunk/mod/mod_lua.html
		pandoc filters
		rspamd
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
		Prosody (high cyclomatic complexity!)
		Redis
		Sile https://github.com/sile-typesetter/sile
		https://github.com/speedata/luaqrcode
		Snort
		Torch https://github.com/torch/image etc
		Varnish
		Vlc https://vlc.verg.ca/
		mpv
			https://github.com/mpv-player/mpv/blob/master/DOCS/man/lua.rst
			https://github.com/CogentRedTester/mpv-scripts
		Wireshark
		Zerobrane https://github.com/pkulchenko/ZeroBraneStudio
		lapis https://github.com/leafo/lapis
		https://love2d.org/
		Torch http://torch.ch/

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
- Документация: общие свойства на основе Lua метатаблиц - https://github.com/luc-tielen/lua-quickcheck/issues/33
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
