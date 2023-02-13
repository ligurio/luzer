## Hacking

For developing `luzer` you need to install required packages. On Debian: `apt
install -y liblua5.1-0-dev llvm-dev libclang-common-13-dev clang cmake`.

```sh
$ cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DENABLE_TESTING=ON -S . -B build
$ cmake --build build --parallel
$ cmake --build build --target test
```

Lua executable (either LuaJIT or PUC Rio Lua) and `liblua` are required for
building the module. By default build system looking for any version of
`liblua` starting from 5.1 installed in a system. One can set specific version
of Lua using CMake flag `LUA_VERSION` and a string with version, for example
`-DLUA_VERSION=5.2`. However, one can build a module with [patched](/patches)
`liblua`: use CMake flag `LUA_PATCHED` for that.

You are ready to make patches!
