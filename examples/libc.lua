-- Fuzzing POSIX libc via Lua FFI

--[[
https://github.com/squeek502/zig-std-lib-fuzzing
https://sourceware.org/glibc/wiki/FuzzingLibc
https://github.com/novafacing/libc-fuzzer
LLVM libc-fuzzer https://gitlab.itwm.fraunhofer.de/kai_plociennik/spu-llvm/-/tree/master/libc/fuzzing
https://forallsecure.com/blog/cve-2020-10029-buffer-overflow-in-gnu-libc-trigonometry-functions
https://android.googlesource.com/toolchain/llvm-project/+/refs/heads/android12-release/libc/fuzzing/
qsort
https://github.com/codenote/regfuzz
regex
https://github.com/novafacing/libmusl
https://man7.org/linux/man-pages/man3/regex.3.html
]]

local luzer = require("luzer")
local has_ffi, ffi = pcall(require, "ffi")

if not has_ffi then
    print("ffi is not found")
    os.exit(1)
end

local libc = ffi.C

ffi.cdef[[
double sin(double x);
float sinf(float x);
long double sinl(long double x);

regex_t re;
regmatch_t matches[10];
int regcomp(regex_t *preg, const char *regex, int cflags);
int regexec(const regex_t *preg, const char *string, size_t nmatch,
            regmatch_t pmatch[], int eflags);
void regfree(regex_t *preg);
]]

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local len = fdp:consume_integer(1, 10000)
    local arg = fdp:consume_number(1, len)
    -- NYI: cannot call this C function (yet)
    --libc.sin(arg)
    --libc.sinf(arg)
    --libc.sinl(arg)

--[[
int i = regcomp(&re, "hello([0-9]*)world", REG_EXTENDED);
assert(i==0);
const char *data = "hello42world";
i = regexec(&re, data, sizeof(matches)/sizeof(matches[0]), (regmatch_t*)&matches,0);
assert(i == 0);
]]
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local args = {
    max_length = 4096,
}

luzer.Fuzz(TestOneInput, nil, args)
