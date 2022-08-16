## Hacking

For developing `luzer` you need to install required packages. On Debian: `apt
install -y liblua5.1-0-dev llvm-dev libclang-common-13-dev clang cmake`.

```sh
$ cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DENABLE_TESTING=ON -S . -B build
$ cmake --build build --parallel
$ cmake --build build --target test
```

You are ready to make patches!
