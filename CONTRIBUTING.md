## Hacking

For developing `luzer` you need to install required packages,
build the project and run the regression tests.

### Setup packages

On Debian: `apt install -y lua5.1 liblua5.1-0-dev llvm-17-dev
libclang-common-17-dev libclang-rt-17-dev clang-17 cmake`.

Note: the sanitizer and libFuzzer runtime libraries and their
headers (`libclang_rt.*`, `fuzzer/`, `sanitizer/`) are shipped in
the `libclang-rt-XX-dev` package, where XX is the Clang version.
On Ubuntu 24.04 `libclang-common-XX-dev` only provides Clang's
builtin headers and is not sufficient on its own (it used to
include the runtime libraries in older releases).

For 32-bit (i386) builds additionally install the multilib
toolchain: `apt install -y gcc-multilib g++-multilib libc6-dev-i386`.

On macOS: `brew install llvm cmake luajit`.

On Nix:

- Build `luzer` package with LuaJIT: `nix build`
- build `luzer` package with PUC Rio Lua 5.4: `nix build .#lua54`
- Developer shell for building `luzer` with LuaJIT: `nix develop`
- Developer shell for building `luzer` with PUC Rio Lua 5.4: `nix develop .#lua54`
- 32-bit (i686) build: `nix build .#packages.i686-linux.default`
  (requires `extra-platforms = i686-linux` in `nix.conf` on an x86_64
  host), 32-bit developer shell: `nix develop .#devShells.i686-linux.default`

### Building

On Debian:

```sh
$ cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DENABLE_TESTING=ON -S . -B build
```

A 32-bit (i386) build on a multilib toolchain (see above) uses the
`i386` CMake preset:

```sh
$ cmake --preset i386
$ cmake --build build-i386 --parallel
$ ctest --preset i386
```

On macOS:

You may need to set environment variables for directories containing
LLVM header files and libraries:

```sh
$ export LDFLAGS="-L$(brew --prefix llvm)/lib"
$ export CPPFLAGS="-I$(brew --prefix llvm)/include"
```

```sh
$ cmake -S . -B build -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ -DLUA_INCLUDE_DIR=/opt/homebrew/include/luajit-2.1 -DLUA_LIBRARIES=/opt/homebrew/lib/libluajit-5.1.dylib -DENABLE_TESTING=ON -DENABLE_LUAJIT=ON -DLUAJIT_FRIENDLY_MODE=ON
```

### Run regression testing

```sh
$ cmake --build build --parallel
$ cmake --build build --target test
```

You are ready to make patches!
