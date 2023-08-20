## Hacking

For developing `luzer` you need to install required packages.

On Debian: `apt install -y liblua5.1-0-dev llvm-17-dev libclang-common-17-dev
libclang-rt-17-dev clang-17 cmake`.

Note: with Clang >= 18 you should install a package
`libclang-rt-XX-dev` and with Clang <= 15 you should install
a package `libclang-common-XX-dev`, where XX is a Clang version.

```sh
$ cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DENABLE_TESTING=ON -S . -B build
$ cmake --build build --parallel
$ cmake --build build --target test
```

You are ready to make patches!
