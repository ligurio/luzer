## Hacking

For developing `luzer` you need to install required packages,
build the project and run the regression tests.

On Debian: `apt install -y liblua5.1-0-dev llvm-17-dev libclang-common-17-dev
libclang-rt-17-dev clang-17 cmake`.

Note: with Clang >= 18 you should install a package
`libclang-rt-XX-dev` and with Clang <= 15 you should install
a package `libclang-common-XX-dev`, where XX is a Clang version.

```sh
$ cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DENABLE_TESTING=ON -S . -B build
```

On macOS: `brew install llvm cmake luajit`

```sh
$ cmake -S . -B build -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ -DLUA_INCLUDE_DIR=/opt/homebrew/include/luajit-2.1 -DLUA_LIBRARIES=/opt/homebrew/lib/libluajit-5.1.dylib -DENABLE_TESTING=ON -DENABLE_LUAJIT=ON -DLUAJIT_FRIENDLY_MODE=ON
```

```sh
$ cmake --build build --parallel
$ cmake --build build --target test
```

You are ready to make patches!
