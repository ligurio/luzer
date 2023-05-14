## Hacking

For developing `luzer` you need to install required packages. On Debian: `apt
install -y liblua5.1-0-dev llvm-17-dev libclang-common-17-dev clang-17 cmake`.

```sh
$ cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DENABLE_TESTING=ON -S . -B build
$ cmake --build build --parallel
$ cmake --build build --target test
```

You are ready to make patches!
