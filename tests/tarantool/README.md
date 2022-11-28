### How to use

- Build Tarantool:
```sh
CFLAGS="-fsanitize=fuzzer-no-link,address" LDFLAGS="-fsanitize=fuzzer-no-link,address" CC=clang-14 CXX=clang++-14 cmake -S . -B build -G Ninja
cmake --build build --parallel
```
- Run tests:
```sh
luarocks install luzer
git clone https://github.com/ligurio/tarantool-corpus
tarantool tarantool_datetime_new.lua
```
