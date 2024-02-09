#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM == 501

static int
countlevels (lua_State *L) {
	lua_Debug ar;
	int li = 1, le = 1;
	/* find an upper bound */
	while (lua_getstack(L, le, &ar)) { li = le; le *= 2; }
	/* do a binary search */
	while (li < le) {
		int m = (li + le)/2;
		if (lua_getstack(L, m, &ar)) li = m + 1;
		else le = m;
	}
	return le - 1;
}

static int
findfield (lua_State *L, int objidx, int level) {
	if (level == 0 || !lua_istable(L, -1))
		return 0;  /* not found */
	lua_pushnil(L);  /* start 'next' loop */
	while (lua_next(L, -2)) {  /* for each pair in table */
		if (lua_type(L, -2) == LUA_TSTRING) {  /* ignore non-string keys */
			if (lua_rawequal(L, objidx, -1)) {  /* found object? */
				lua_pop(L, 1);  /* remove value (but keep name) */
				return 1;
			}
			else if (findfield(L, objidx, level - 1)) {  /* try recursively */
				lua_remove(L, -2);  /* remove table (but keep name) */
				lua_pushliteral(L, ".");
				lua_insert(L, -2);  /* place '.' between the two names */
				lua_concat(L, 3);
				return 1;
			}
		}
		lua_pop(L, 1);  /* remove value */
	}
	return 0;  /* not found */
}

int
lua_absindex (lua_State *L, int i) {
	if (i < 0 && i > LUA_REGISTRYINDEX)
		i += lua_gettop(L) + 1;
	return i;
}

void
lua_copy (lua_State *L, int from, int to) {
	int abs_to = lua_absindex(L, to);
	luaL_checkstack(L, 1, "not enough stack slots");
	lua_pushvalue(L, from);
	lua_replace(L, abs_to);
}

static int
pushglobalfuncname (lua_State *L, lua_Debug *ar) {
	int top = lua_gettop(L);
	lua_getinfo(L, "f", ar);  /* push function */
	lua_pushvalue(L, LUA_GLOBALSINDEX);
	if (findfield(L, top + 1, 2)) {
		lua_copy(L, -1, top + 1);  /* move name to proper place */
		lua_pop(L, 2);  /* remove pushed values */
		return 1;
	}
	else {
		lua_settop(L, top);  /* remove function and global table */
		return 0;
	}
}

static void
pushfuncname (lua_State *L, lua_Debug *ar) {
	if (*ar->namewhat != '\0')  /* is there a name? */
		lua_pushfstring(L, "function " LUA_QS, ar->name);
	else if (*ar->what == 'm')  /* main? */
		lua_pushliteral(L, "main chunk");
	else if (*ar->what == 'C') {
		if (pushglobalfuncname(L, ar)) {
			lua_pushfstring(L, "function " LUA_QS, lua_tostring(L, -1));
			lua_remove(L, -2);  /* remove name */
		}
		else
			lua_pushliteral(L, "?");
	}
	else
		lua_pushfstring(L, "function <%s:%d>", ar->short_src, ar->linedefined);
}

#define LEVELS1 12  /* size of the first part of the stack */
#define LEVELS2 10  /* size of the second part of the stack */

void
luaL_traceback (lua_State *L, lua_State *L1,
				const char *msg, int level) {
	lua_Debug ar;
	int top = lua_gettop(L);
	int numlevels = countlevels(L1);
	int mark = (numlevels > LEVELS1 + LEVELS2) ? LEVELS1 : 0;
	if (msg) lua_pushfstring(L, "%s\n", msg);
	lua_pushliteral(L, "stack traceback:");
	while (lua_getstack(L1, level++, &ar)) {
		if (level == mark) {  /* too many levels? */
			lua_pushliteral(L, "\n\t...");  /* add a '...' */
			level = numlevels - LEVELS2;  /* and skip to last ones */
		}
		else {
			lua_getinfo(L1, "Slnt", &ar);
			lua_pushfstring(L, "\n\t%s:", ar.short_src);
			if (ar.currentline > 0)
				lua_pushfstring(L, "%d:", ar.currentline);
				lua_pushliteral(L, " in ");
				pushfuncname(L, &ar);
				lua_concat(L, lua_gettop(L) - top);
		}
	}
	lua_concat(L, lua_gettop(L) - top);
}

#endif
