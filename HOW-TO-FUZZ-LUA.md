# Расширяем поддержку языков для AFL и LibFuzzer на примере Lua

Тестирования мало не бывает и мы решили применить рандомизированное
тестирование для Lua API в Tarantool. К сожалению готовых инструментов для
фаззинга скриптов на Lua не существует и нам пришлось сделать их самим. Я
расскажу о том, как использовать American Fuzzy Lop и LibFuzzer для фаззинга
программ на Lua. Доклад будет интересен всем, кто разрабатывает ПО с высокими
требованиями к качеству и стабильности и интересуется рандомизированным
тестированием.

## Зачем?

- тарантул состоит из нескольких компонентов: LuaJIT, сервера приложений, функциональность СУБД и др.
- Пользователь может взаимодействовать с Tarantool с помощью SQL, Lua API и в исключительных случаях C API.
- сервер приложений состоит из большого количества модулей написанных на Си с оберткой на Lua или чистом Lua
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

## Подходы

- готовых иинструментов для фаззинга программ на Lua нет, возможно из-за небольшого размера сообщества вокруг языка Lua
- есть lua-quickcheck, аналог Hypothesis для Python, но он очень скромный по возможностям
- есть форк интерпретатора Lua c патчами для фаззинга https://github.com/stevenjohnstone/afl-lua
- писать свой фаззер с нуля неэффективно
- самые популярные движки: AFL, LibFuzzer, hongfuzz. Принцип как и в статическом анализе: механизм работы тулов немного отличается и лучше использовать несколько разных, а не один из них.
- Интеграция популярных движков с Lua!

## Интеграция с AFL

- для AFL есть интеграция с Python, Ruby
- давайте сделаем интеграцию с Lua
- AFL++/AFL поддерживают интеграцию с помощью тн forkserver
- AFL и вспомогательный модуль взаимодействуют через разделяемую область в памяти, где сохраняется информация о покрытых базовых блоках (aka basic blocks)
- вспомогательный модуль с помощью стандартной библиотеки записывает информацию о покрытых блоках в разделяемую память
- AFL генерирует новые данные для фаззинга с учетом информации о покрытых блоках

## Интеграция с LibFuzzer

- изначально LibFuzzer создавали для C/C++
- потом появились интеграции для LibFuzzer с Python, Java
- давайте сделаем интеграцию с Lua
- рассказать как LibFuzzer интегрируется с Lua
- рассказать FuzzedDataProvider

## Демо с лабиринтом

- TODO
- https://github.com/RUB-SysSec/ijon-data/tree/master/ijon-data
