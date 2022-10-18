- "Segmentation fault on msgpack decoding"
https://github.com/tarantool/tarantool/issues/7818
- "Wrong datetime calculation (A - B + B != A)"
https://github.com/tarantool/tarantool/issues/7145

~$ cat sample.lua
a = "aaaa",
print(a)
~$ tarantool sample.lua
nil
~$
