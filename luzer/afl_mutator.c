/******************************************************************************
* Copyright (C) 2022 Sergey Bronnikov
* Copyright (C) 2020 Steven Johnstone
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************/

#include <assert.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char *mutator_env = "AFL_CUSTOM_MUTATOR_LUA_SCRIPT";
static const char *mutator_script_default = "./afl_mutator.lua";
static const int default_havoc_mutation_probability = 6;

#define METHODS                                                                \
  X(init)                                                                      \
  X(fuzz)                                                                      \
  X(post_process)                                                              \
  X(init_trim)                                                                 \
  X(trim)                                                                      \
  X(post_trim)                                                                 \
  X(havoc_mutation)                                                            \
  X(havoc_mutation_probability)                                                \
  X(queue_get)                                                                 \
  X(queue_new_entry)

#define xstr(s) str(s)
#define str(s) #s

#define LUA_OK 0

struct state {
  lua_State *L;
  void *trim_buf;
#define X(name)                                                                \
  int afl_custom_##name##_enabled;                                             \
  const char *afl_custom_##name##_method;
  METHODS
#undef X
};

static struct state *new_state(void) {
  const char *mutator_script = getenv(mutator_env) ? "XXX" : mutator_script_default;
  struct state *s = calloc(1, sizeof(struct state));
  assert(s);
  s->L = luaL_newstate();
  assert(s->L);
  luaL_openlibs(s->L);
  int rc = luaL_dofile(s->L, mutator_script);
  (void)rc;
  assert(rc == LUA_OK);
#define X(name)                                                                \
  {                                                                            \
    lua_getglobal(s->L, str(name));                                            \
    if (lua_isfunction(s->L, -1)) {                                            \
      s->afl_custom_##name##_enabled = 1;                                      \
      s->afl_custom_##name##_method = str(name);                               \
    }                                                                          \
    lua_settop(s->L, 0);                                                       \
  }
  METHODS
#undef X
  return s;
}

void *afl_custom_init(void *afl, unsigned int seed) {
  struct state *s = new_state();
  if (!s->afl_custom_init_enabled) {
    return s;
  }
  lua_getglobal(s->L, s->afl_custom_init_method);
  lua_pushinteger(s->L, seed);
  const int rc = lua_pcall(s->L, 1, 0, 0);
  (void)rc;
  assert(rc == LUA_OK);
  lua_settop(s->L, 0);
  return (void *)s;
}

size_t afl_custom_fuzz(void *data, char *buf, size_t buf_size, char **out_buf,
                       char *add_buf, size_t add_buf_size, size_t max_size) {
  struct state *s = (struct state *)data;
  if (!s->afl_custom_fuzz_enabled) {
    *out_buf = buf;
    return buf_size;
  }
  lua_getglobal(s->L, s->afl_custom_fuzz_method);
  size_t args = 2;
  lua_pushlstring(s->L, buf, buf_size);
  lua_pushinteger(s->L, max_size);
  if (add_buf) {
    lua_pushlstring(s->L, add_buf, add_buf_size);
    args++;
  }
  const int rc = lua_pcall(s->L, args, 1, 0);
  (void)rc;
  assert(rc == LUA_OK);
  size_t rstr_len;
  const char *rstr = lua_tolstring(s->L, -1, &rstr_len);
  assert(rstr);
  lua_settop(s->L, 0);
  rstr_len = rstr_len > max_size ? max_size : rstr_len;
  *out_buf = malloc(rstr_len);
  assert(*out_buf);
  memcpy(*out_buf, rstr, rstr_len);
  return rstr_len;
}

size_t afl_custom_post_process(void *data, char *buf, size_t buf_size,
                               char **out_buf) {
  struct state *s = (struct state *)data;
  if (!s->afl_custom_post_process_enabled) {
    *out_buf = buf;
    return buf_size;
  }
  lua_getglobal(s->L, s->afl_custom_post_process_method);
  lua_pushlstring(s->L, buf, buf_size);
  const int rc = lua_pcall(s->L, 1, 1, 0);
  (void)rc;
  assert(rc == LUA_OK);
  size_t rstr_len;
  const char *rstr = lua_tolstring(s->L, -1, &rstr_len);
  assert(rstr);
  lua_settop(s->L, 0);
  *out_buf = malloc(rstr_len);
  assert(*out_buf);
  memcpy(*out_buf, rstr, rstr_len);
  return rstr_len;
}

int32_t afl_custom_init_trim(void *data, char *buf, size_t buf_size) {
  struct state *s = (struct state *)data;
  if (!s->afl_custom_init_trim_enabled) {
    return 0;
  }
  lua_getglobal(s->L, s->afl_custom_init_trim_method);
  lua_pushlstring(s->L, buf, buf_size);
  const int rc = lua_pcall(s->L, 1, 1, 0);
  (void)rc;
  assert(rc == LUA_OK);
  const int rv = lua_tointeger(s->L, -1);
  lua_settop(s->L, 0);
  return (uint32_t)(0xffffffff & rv);
}

size_t afl_custom_trim(void *data, char **out_buf) {
  struct state *s = (struct state *)data;
  if (!s->afl_custom_trim_enabled) {
    return 0;
  }
  lua_getglobal(s->L, s->afl_custom_trim_method);
  const int rc = lua_pcall(s->L, 0, 1, 0);
  (void)rc;
  assert(rc == LUA_OK);
  size_t rstr_len;
  const char *rstr = lua_tolstring(s->L, -1, &rstr_len);
  assert(rstr);
  if (s->trim_buf) {
    free(s->trim_buf);
  }
  s->trim_buf = malloc(rstr_len);
  assert(s->trim_buf);
  memcpy(s->trim_buf, rstr, rstr_len);
  lua_settop(s->L, 0);
  *out_buf = s->trim_buf;
  return rstr_len;
}

int32_t afl_custom_post_trim(void *data, int success) {
  struct state *s = (struct state *)data;
  if (!s->afl_custom_post_trim_enabled) {
    return 0;
  }
  lua_getglobal(s->L, s->afl_custom_post_trim_method);
  lua_pushboolean(s->L, !!success);
  const int rc = lua_pcall(s->L, 1, 1, 0);
  (void)rc;
  assert(rc == LUA_OK);
  const int rv = lua_tointeger(s->L, -1);
  lua_settop(s->L, 0);
  return (uint32_t)(0xffffffff & rv);
}

size_t afl_custom_havoc_mutation(void *data, char *buf, size_t buf_size,
                                 char **out_buf, size_t max_size) {
  struct state *s = (struct state *)data;
  if (!s->afl_custom_havoc_mutation_enabled) {
    *out_buf = buf;
    return buf_size;
  }
  lua_getglobal(s->L, s->afl_custom_havoc_mutation_method);
  lua_pushlstring(s->L, buf, buf_size);
  lua_pushinteger(s->L, max_size);
  const int rc = lua_pcall(s->L, 2, 1, 0);
  (void)rc;
  assert(rc == LUA_OK);
  size_t rstr_len;
  const char *rstr = lua_tolstring(s->L, -1, &rstr_len);
  assert(rstr);
  lua_settop(s->L, 0);
  rstr_len = rstr_len > max_size ? max_size : rstr_len;
  *out_buf = malloc(rstr_len);
  assert(*out_buf);
  memcpy(*out_buf, rstr, rstr_len);
  return rstr_len;
}

uint8_t afl_custom_havoc_mutation_probability(void *data) {
  struct state *s = (struct state *)data;
  if (!s->afl_custom_havoc_mutation_enabled) {
    return 0;
  }
  if (!s->afl_custom_havoc_mutation_probability_enabled) {
    return default_havoc_mutation_probability;
  }
  lua_getglobal(s->L, s->afl_custom_havoc_mutation_probability_method);
  const int rc = lua_pcall(s->L, 0, 1, 0);
  (void)rc;
  assert(rc == LUA_OK);
  const int rv = lua_tointeger(s->L, -1);
  lua_settop(s->L, 0);
  return (uint8_t)(0xff & rv);
}

uint8_t afl_custom_queue_get(void *data, const char *filename) {
  struct state *s = (struct state *)data;
  if (!s->afl_custom_queue_get_enabled) {
    return 1;
  }
  lua_getglobal(s->L, s->afl_custom_queue_get_method);
  lua_pushstring(s->L, filename);
  const int rc = lua_pcall(s->L, 1, 1, 0);
  (void)rc;
  assert(rc == LUA_OK);
  const int rv = lua_toboolean(s->L, -1);
  lua_settop(s->L, 0);
  return (uint8_t)(0xff & rv);
}

void afl_custom_queue_new_entry(void *data, const char *filename_new_queue,
                                const char *filename_orig_queue) {
  struct state *s = (struct state *)data;
  if (!s->afl_custom_queue_new_entry_enabled) {
    return;
  }
  lua_getglobal(s->L, s->afl_custom_queue_new_entry_method);
  lua_pushstring(s->L, filename_new_queue);
  lua_pushstring(s->L, filename_orig_queue);
  const int rc = lua_pcall(s->L, 2, 0, 0);
  (void)rc;
  assert(rc == LUA_OK);
  lua_settop(s->L, 0);
  return;
}

void afl_custom_deinit(void *data) {
  struct state *s = (struct state *)data;
  lua_close(s->L);
  free(s);
}
