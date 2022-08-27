## Hacking

For developing `luzer` you need to install packages with libraries and headers
and CMake. On Debian: `apt install -y liblua5.1-0-dev libclang-common-13-dev
clang cmake`.

```sh
$ cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -S . -B build
$ cmake --build build --parallel
$ cmake --build build --target test
```

You are ready to make patches!
