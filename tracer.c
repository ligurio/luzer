#include <lua.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h> /* TODO: remove */

#include "macros.h"

int __sanitizer_cov_trace_basic_block(int id) {
       return id;
}

/**
 * From afl-python
 * https://github.com/jwilk/python-afl/blob/8df6bfefac5de78761254bf5d7724e0a52d254f5/afl.pyx#L74-L87
 */
#define LHASH_INIT       0x811C9DC5
#define LHASH_MAGIC_MULT 0x01000193
#define LHASH_NEXT(x)    h = ((h ^ (unsigned char)(x)) * LHASH_MAGIC_MULT)

static inline unsigned int lhash(const char *key, size_t offset) {
    const char *const last = &key[strlen(key) - 1];
    uint32_t h = LHASH_INIT;
    while (key <= last)               LHASH_NEXT(*key++);
    for (; offset != 0; offset >>= 8) LHASH_NEXT(offset);
    return h;
}

static unsigned int current_location;

void hook(lua_State *L, lua_Debug *ar) {
	// TODO: skip when 'info.what == "C"'
    lua_getinfo(L, "Sln", ar);
    if (ar && ar->source && ar->currentline) {
        //const unsigned int new_location = lhash(ar->source, ar->currentline) % afl_shm_size;
        const unsigned int new_location = lhash(ar->source, ar->currentline);
        //afl_shm[current_location ^ new_location] += 1;
        current_location = new_location / 2;
    }
	//printf("=====================================================\n");
	//printf("ar->linedefined %d\n", ar->linedefined);
	//printf("ar->currentline %d\n", ar->currentline);
	//printf("ar->lastlinedefined %d\n", ar->lastlinedefined);
	//printf("ar->source %s\n", ar->source);
	//printf("ar->short_src %s\n", ar->short_src);
	//printf("ar->what (Lua/C) %s\n", ar->what);
	//printf("=====================================================\n");
    //__sanitizer_cov_trace_cmp8(1, 2);
	//__sanitizer_cov_trace_pc();
	__sanitizer_cov_trace_basic_block(current_location);
}
