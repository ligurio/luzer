#ifndef LUZER_TRACER_H_
#define LUZER_TRACER_H_

void debug_hook(lua_State *L, lua_Debug *ar);
void collector_debug_hook(lua_State *L, lua_Debug *ar);

#endif  // LUZER_TRACER_H_
