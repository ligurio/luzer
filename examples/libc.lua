-- Fuzzing POSIX libc
--
-- https://github.com/squeek502/zig-std-lib-fuzzing
-- https://sourceware.org/glibc/wiki/FuzzingLibc
-- https://github.com/novafacing/libc-fuzzer
-- LLVM libc-fuzzer https://gitlab.itwm.fraunhofer.de/kai_plociennik/spu-llvm/-/tree/master/libc/fuzzing
-- https://forallsecure.com/blog/cve-2020-10029-buffer-overflow-in-gnu-libc-trigonometry-functions
-- https://android.googlesource.com/toolchain/llvm-project/+/refs/heads/android12-release/libc/fuzzing/
-- qsort
-- https://github.com/codenote/regfuzz
-- regex
-- https://github.com/novafacing/libmusl

local luzer = require("luzer")
local has_ffi, ffi = pcall(require, "ffi")
local libc = require("libc")

ffi.cdef[[
int chmod(const char *pathname, uint32_t mode);
]]

ffi.C.chmod("xxx", 493--[[rwxr-xr-x]])

local function TestOneInput(buf, _size)
end

luzer.Setup(arg, TestOneInput)
luzer.Fuzz()
