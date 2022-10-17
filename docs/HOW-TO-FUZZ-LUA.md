# Расширяем поддержку языков для AFL и LibFuzzer на примере Lua

Тестирования мало не бывает и мы решили применить рандомизированное
тестирование для Lua API в Tarantool. К сожалению готовых инструментов для
фаззинга скриптов на Lua не существует и нам пришлось сделать их самим. Я
расскажу о том, как использовать American Fuzzy Lop и LibFuzzer для фаззинга
программ на Lua. Доклад будет интересен всем, кто разрабатывает ПО с высокими
требованиями к качеству и стабильности и интересуется рандомизированным
тестированием.

https://cyruscyliu.github.io/posts/2021-11-02-libFuzzer-cov-control/
https://go-talks.appspot.com/github.com/dvyukov/go-fuzz/slides/go-fuzz.slide
https://go-talks.appspot.com/github.com/dvyukov/go-fuzz/slides/fuzzing.slide
http://taviso.decsystem.org/making_software_dumber.pdf

## Зачем?

- тарантул состоит из нескольких компонентов: LuaJIT, сервера приложений,
функциональность СУБД и др.
- Пользователь может взаимодействовать с Tarantool с помощью SQL, Lua API и в
исключительных случаях C API.
- сервер приложений состоит из большого количества модулей написанных на Си с
оберткой на Lua или чистом Lua
- все модули покрываются регресионными тестами, но этого не всегда достаточно
- нужно дополнительное тестирование - Фаззинг!

- http://antirez.com/news/119

A bit more than one month ago I received an email from the Apple Information
Security team. During an auditing the Apple team found a security issue in the
Redis Lua subsystem, specifically in the cmsgpack library. The library is not
part of Lua itself, it is an implementation of MessagePack I wrote myself. In
the course of merging a pull request improving the feature set, a security
issue was added. Later the same team found a new issue in the Lua struct
library, again such library was not part of Lua itself, at least in the release
of Lua we use: we just embedded the source code inside our Lua implementation
in order to provide some functionality to the Lua interpreter that is available
to Redis users. Then I found another issue in the same struct package, and
later the Alibaba team found many other issues in cmsgpack and other code paths
using the Lua API. In a short amount of time I was sitting on a pile of Lua
related vulnerabilities.

```
string.strip (Lua) ->
	string_strip (Lua) ->
		ffi.C.string_strip_helper (LuaJIT FFI) ->
			string_strip_helper (C) ->
				libc (C)

msgpack.decode (Lua) ->
	luamp_iterator_decode (Lua C API) ->
		luamp_iterator_decode (Lua C API) ->
			luamp_decode (Lua C API) ->
				msgpuck

datetime.parse (Lua) ->
	datetime_parse_from (Lua) ->
		builtin.tnt_datetime_strptime (LuaJIT FFI) ->
			tnt_datetime_strptime (C) ->
				datetime_strptime (C) ->
					tm_to_datetime (C)
```

## Подходы

- готовых инструментов для фаззинга программ на Lua нет, возможно из-за
  небольшого размера сообщества вокруг языка Lua
- есть lua-quickcheck, аналог Hypothesis для Python, но он очень скромный по возможностям
- есть форк интерпретатора Lua c патчами для фаззинга https://github.com/stevenjohnstone/afl-lua
- писать свой фаззер с нуля неэффективно
- самые популярные движки: AFL, LibFuzzer, hongfuzz. Принцип как и в
статическом анализе: механизм работы тулов немного отличается и лучше
использовать несколько разных, а не один из них.
	- https://habr.com/ru/company/bizone/blog/570312/
- Интеграция популярных движков с Lua! https://www.fuzzbench.com/reports/sample/index.html

## Интеграция с AFL

- https://lcamtuf.coredump.cx/afl/technical_details.txt
- https://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html
- https://github.com/google/fuzzing/blob/master/docs/afl-based-fuzzers-overview.md
- https://aflplus.plus/rC3_talk_2020.pdf
- https://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html
- для AFL есть интеграция с Python, Ruby
- давайте сделаем интеграцию с Lua
- AFL++/AFL поддерживают интеграцию с помощью тн forkserver
- AFL и вспомогательный модуль взаимодействуют через разделяемую область в
памяти, где сохраняется информация о покрытых базовых блоках (aka basic blocks)
- вспомогательный модуль с помощью стандартной библиотеки записывает информацию
о покрытых блоках в разделяемую память
- AFL генерирует новые данные для фаззинга с учетом информации о покрытых блоках

## Интеграция с LibFuzzer

- изначально LibFuzzer создавали для C/C++
- потом появились интеграции для LibFuzzer с Python, Java
- давайте сделаем интеграцию с Lua
- рассказать как LibFuzzer интегрируется с Lua
- рассказать FuzzedDataProvider

## Call to action

выберите любую функцию и напишите фаззинг тест для нее

- Swift https://github.com/apple/swift/blob/main/docs/libFuzzerIntegration.md
- Java https://github.com/CodeIntelligenceTesting/jazzer
- Python https://github.com/fuzzitdev/pythonfuzz
- Python https://github.com/google/atheris
- Python https://pypi.org/project/atheris-libprotobuf-mutator/
- Python https://pypi.org/project/pyfuzzer/
- Javascript https://github.com/guidovranken/libfuzzer-js
- Javascript https://github.com/fuzzitdev/jsfuzz
- Rust https://github.com/rust-fuzz/cargo-fuzz
- Go https://github.com/dvyukov/go-fuzz

custom mutators:
- https://github.com/MozillaSecurity/libfuzzer-python-bridge
- Lua

## Демо с лабиринтом

- грамматики https://github.com/mozilla-services/lua_sandbox_extensions/tree/main/lpeg/modules/lpeg
- https://github.com/stevenjohnstone/afl-lua/tree/v5.3/examples/maze
- https://github.com/RUB-SysSec/ijon-data/tree/master/ijon-data
