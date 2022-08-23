## Зачем?

- тарантул состоит из рантайма (LuaJIT), сервера приложений и др
- сервер приложений состоит из большого количества сишных библиотек с оберткой на Lua (FFI, Lua C API)
- модули покрываются тестами, но этого недостаточно
- нужно дополнительное тестирование
- Фаззинг!

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

## подходы

- https://github.com/stevenjohnstone/afl-lua
- писать свой фаззер с нуля неэффективно
- самые популярные движки: AFL, LibFuzzer, hongfuzz
- интеграция!

## Интеграция с AFL

- для AFL есть интеграция с Python, Ruby
- давайте сделаем интеграцию с Lua
- ...

## Интеграция с LibFuzzer

- для AFL есть интеграция с Python, Java
- давайте сделаем интеграцию с Lua
- ...

## Демо с лабиринтом

- https://github.com/RUB-SysSec/ijon-data/tree/master/ijon-data
