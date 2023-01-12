# Usecases

## Fuzzing C library

Lua has a FFI library that allows seamless integration with C/C++ libraries.
LuaJIT has a builtin FFI library, see https://luajit.org/ext_ffi.html

Build C library with "-fsanitize=fuzzer-no-link,address".
Create a fuzzing target.
Run fuzzing target.

`examples/example_zlib.lua`

## Fuzzing builtin Lua functions and Lua runtimes

`luzer` is useful for testing builtin Lua functions. This example describes
fuzzing testing of builtin Lua function.

Download archive with Lua 5.4 source code on [download
page](https://www.lua.org/download.html) and unpack archive:

```sh
curl -O https://www.lua.org/ftp/lua-5.4.4.tar.g
tar xvzf lua-5.4.4.tar.gz
```

Build Lua interpreter with `-fsanitize=fuzzer-no-link,undefined`.
Set `CFLAGS` and `LDFLAGS`:

```diff
--- src/Makefile        2022-12-07 10:44:14.802317400 +0300
+++ src/Makefile        2022-12-07 10:44:18.286328297 +0300
@@ -7,6 +7,7 @@
 PLAT= guess
 
 CC= gcc -std=gnu99
+CC= clang
 CFLAGS= -O2 -Wall -Wextra -DLUA_COMPAT_5_3 $(SYSCFLAGS) $(MYCFLAGS)
 LDFLAGS= $(SYSLDFLAGS) $(MYLDFLAGS)
 LIBS= -lm $(SYSLIBS) $(MYLIBS)
@@ -20,8 +21,8 @@
 SYSLDFLAGS=
 SYSLIBS=
 
-MYCFLAGS=
-MYLDFLAGS=
+MYCFLAGS=-fsanitize=fuzzer-no-link,undefined
+MYLDFLAGS=-fsanitize=fuzzer-no-link,undefined
 MYLIBS=
 MYOBJS=

```

Create a fuzzing target.
Run fuzzing target with instrumented Lua runtime.

TODO: reproduce
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-15945
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24369
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24370

## Fuzzing pure Lua external modules

TODO

## Fuzzing C Extensions

Setup module using `luarocks`:

```
$ luarocks install --tree modules --lua-version 5.1 lua-cjson CC="clang" CFLAGS="-ggdb -fPIC -fsanitize=address" LDFLAGS="-fsanitize=address"

Installing https://luarocks.org/lua-cjson-2.1.0.6-1.src.rock

lua-cjson 2.1.0.6-1 depends on lua >= 5.1 (5.1-1 provided by VM)
clang -ggdb -fPIC -fsanitize=address -I/usr/include/lua5.1 -c lua_cjson.c -o lua_cjson.o
clang -ggdb -fPIC -fsanitize=address -I/usr/include/lua5.1 -c strbuf.c -o strbuf.o
clang -ggdb -fPIC -fsanitize=address -I/usr/include/lua5.1 -c fpconv.c -o fpconv.o
gcc -shared -o cjson.so lua_cjson.o strbuf.o fpconv.o
No existing manifest. Attempting to rebuild...
lua-cjson 2.1.0.6-1 is now installed in /home/sergeyb/sources/luzer/build/modules (license: MIT)
```

```
$ export LUA_PATH="$LUA_PATH;modules/lib/lua/5.1/?.lua"
$ export LUA_CPATH="$LUA_CPATH;modules/lib/lua/5.1/?.so;./?.so"
$ mkdir cjson-corpus
$ echo -n "{}" > cjson-corpus/sample
$ luajit luzer_example_json.lua
```

TODO:

- https://github.com/google/atheris/blob/master/native_extension_fuzzing.md
- "Fuzzing native Python extensions with Atheris" https://www.youtube.com/watch?v=oM-7lt43-GA
- https://github.com/google/atheris/blob/master/native_extension_fuzzing.md
