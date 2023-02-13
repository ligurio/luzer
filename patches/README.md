## Patches

these patches are intended to make Lua runtimes make more fuzzing friendly.

NOTE: For using module with these pathes you need to patch `liblua` as well as
patched Lua runtime used for running tests.

**Add a new hook type `edge`**

New hook calls a predefined function on following instructions: (`OP_TEST`,
`OP_TESTSET`, `OP_CALL`, `OP_TAILCALL`, `OP_TFORLOOP`, `OP_FORLOOP`).

```lua
local function trace(event, line)
  local info = debug.getinfo(1, "Sl")
end

debug.sethook(trace, "e")

local a
if a == "XXXX" then print() end
```

Lua reference manual defines a debug interface that contains a quite limited
data. See https://www.lua.org/manual/5.4/manual.html#lua_Debug. Patch adds a
new field `pc` to a structure `lua_Debug`.

```c
typedef struct lua_Debug {
  int event;
  const char *name;           /* (n) */
  const char *namewhat;       /* (n) */
  const char *what;           /* (S) */
  const char *source;         /* (S) */
  size_t srclen;              /* (S) */
  int currentline;            /* (l) */
  int linedefined;            /* (S) */
  int lastlinedefined;        /* (S) */
  unsigned char nups;         /* (u) number of upvalues */
  unsigned char nparams;      /* (u) number of parameters */
  char isvararg;              /* (u) */
  char istailcall;            /* (t) */
  unsigned short ftransfer;   /* (r) index of first value transferred */
  unsigned short ntransfer;   /* (r) number of transferred values */
  char short_src[LUA_IDSIZE]; /* (S) */
  /* private part */
  other fields
} lua_Debug;
```

**Add a new hook type `data`**

New hook calls a predefined function on comparison instructions `OP_EQ`,
`OP_LE`, and `OP_LT` and adds first and second operand to a structure returned
by `debug.getinfo`.

```lua
local function trace(event, line)
  local info = debug.getinfo(1, "SlC")
end

debug.sethook(trace, "d")

local a
if a == "XXXX" then print() end
```

**Add a storage**

```c
volatile unsigned char *__afl_global_area_ptr;
volatile unsigned int __afl_prev_loc = 0;
volatile unsigned int __afl_enabled = 1;
const size_t __afl_shm_size = sizeof(__afl_area_initial);

/* For ijon like functionality */
volatile unsigned int __afl_state = 0;
volatile unsigned int __afl_state_log = 0;

unsigned int *__afl_scratch_area = afl_scratch_storage;
const size_t __afl_scratch_area_size = sizeof(afl_scratch_storage);
```

| Lua             |  Hook "edge"  | Hook "data" |
|-----------------|:-------------:|------------:|
| PUC Rio Lua 5.1 |  No           | No          |
| PUC Rio Lua 5.2 |  No           | No          |
| PUC Rio Lua 5.3 |  Yes          | No          |
| PUC Rio Lua 5.4 |  No           | No          |
| LuaJIT          |  Yes          | Yes         |


### Во что разворачивается `-fsanitize=fuzzer`?

```
-fsanitize-coverage-type=1
-fsanitize-coverage-type=3
-fsanitize-coverage-indirect-calls
-fsanitize-coverage-trace-cmp
-fsanitize-coverage-inline-8bit-counters
-fsanitize-coverage-pc-table
-fsanitize-coverage-stack-depth
-fsanitize=fuzzer,fuzzer-no-link
<!--
-fno-builtin-bcmp
-fno-builtin-memcmp
-fno-builtin-strncmp
-fno-builtin-strcmp
-fno-builtin-strncasecmp
-fno-builtin-strcasecmp
-fno-builtin-strstr
-fno-builtin-strcasestr
-fno-builtin-memmem
-->
```

Опции для инструментирования которые использует libFuzzer:

```
-fsanitize-coverage-indirect-calls
-fsanitize-coverage-trace-cmp
-fsanitize-coverage-inline-8bit-counters
-fsanitize-coverage-pc-table
-fsanitize-coverage-stack-depth
```

`-fsanitize-coverage=inline-8bit-counters` compiler option instructs the
compiler to add an inline counter increment on every relevant edge. This option
also adds a call to extern "C" void `__sanitizer_cov_8bit_counters_init(uint8_t
*start, uint8_t *stop)` that you must implement. The arguments correspond to the
start and end of an array that contains all the 8-bit counters created.

### Инструментирование Lua

OP-коды c ветвлениями `__sanitizer_cov_trace_pc`

- `OP_RETURN`
- `OP_JMP`

Аргументы операторов сравнения `__sanitizer_cov_trace_cmp`
https://llvm.org/docs/LibFuzzer.html#tracing-cmp-instructions
https://llvm.org/docs/LibFuzzer.html#value-profile

- `OP_EQ`
- `OP_LT`
- `OP_LE`

Аргументы операции деления `__sanitizer_cov_trace_div*`

- `OP_DIV`

Индексы элементов массива `__sanitizer_cov_trace_gep`

Загрузка переменных `__sanitizer_cov_load*`

- `OP_LOADNIL`
- `OP_LOADK`
- `OP_LOADBOOL`

Сохранение переменных `__sanitizer_cov_store*`

Проверка покрытия условий: TEST, TESTSET (важно для измерения покрытия кода)

```
	[0] ~$ luac -l - <<< "local a,b; a = a and b"
	[0] ~$ luac -l - <<< "local a,b,c; c = a or b"
```

### Материалы:

- https://clang.llvm.org/docs/SanitizerCoverage.html
- https://github.com/devcat-studio/lua-5.1.5-op_halt
- https://the-ravi-programming-language.readthedocs.io/en/latest/lua_bytecode_reference.html#instruction-notation
- Исходники https://github.com/microsoft/compiler-rt/tree/master/lib/sanitizer_common
- https://learn.microsoft.com/en-us/cpp/build/reference/fsanitize-coverage?view=msvc-170
- https://the-ravi-programming-language.readthedocs.io/en/latest/lua_bytecode_reference.html#op-test-and-op-testset-instructions
- https://ujit.readthedocs.io/en/latest/public/bytecode-ref.html#comparison
