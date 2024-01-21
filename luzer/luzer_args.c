/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright 2022-2023, Sergey Bronnikov
 */

#include <lauxlib.h>
#include <stdlib.h>
#include <string.h>

#include "luzer_args.h"
#include "macros.h"

#define ENV_NOT_USE_CLI_ARGS "LUZER_NOT_USE_CLI_ARGS"

#define SEED_CORPUS_PATH_FLAG "-corpus"

#define FLAG_SCANF_FORMAT_KEY "-%[^=]"
#define FLAG_PATTERN_KEY "-%s="
#define FLAG_PATTERN_KEY_VALUE "-%s=%s"
#define FLAG_PATTERN_OVERHEAD 2
#define FLAG_FULL_SIZE(flag) (strlen(flag) + FLAG_PATTERN_OVERHEAD)

/* Structure for convenient argument parsing. */
typedef struct {
	char **argv;
	int argc;
} luzer_args;

NO_SANITIZE static bool
is_flag_in_args(luzer_args *f_args, const char *key) {
	if (!f_args || !f_args->argv || f_args->argc <= 1) {
                return false;
        }

        size_t flag_size = FLAG_FULL_SIZE(key);
	/* +1 for null terminated */
        char flag[flag_size + 1];
	snprintf(flag, flag_size + 1, FLAG_PATTERN_KEY, key);
	for (int i = 0; i < f_args->argc; i++) {
		if (strncmp(f_args->argv[i], flag, flag_size) == 0) {
                        return true;
                }
	}
	return false;
}

NO_SANITIZE static int
add_arg_with_mem_allocation(luzer_args *l_args, char *arg) {
        char **argvp = realloc(l_args->argv, sizeof(char*) * (l_args->argc + 1));
        if (argvp == NULL) {
                return -1;
        }
        l_args->argv = argvp;
        l_args->argv[l_args->argc] = arg;
        return 0;
}

NO_SANITIZE static int
luaL_get_args_from_cli(lua_State *L, luzer_args *cli_args) {
	lua_getglobal(L, "arg");

	cli_args->argv = malloc(1 * sizeof(char*));
	if (!cli_args->argv) {
                return -1;
        }

	lua_pushnil(L);

        bool use_cli_args = !getenv(ENV_NOT_USE_CLI_ARGS);
	/* Zero arg is reserved for program name. */
        cli_args->argc = 1;
	while (lua_next(L, -2) != 0) {
		const char *value = lua_tostring(L, -1);
		const int key = lua_tointeger(L, -2);
		lua_pop(L, 1);

                if (key < 0) {
                        continue;
                }

                const char *arg = strdup(value);
                if (!arg) {
                        return -1;
                }

                if (key == 0) {
                        cli_args->argv[0] = (char*)arg;
                        continue;
                }

                if (use_cli_args) {
                        if (add_arg_with_mem_allocation(cli_args, (char*)arg)) {
                                return -1;
                        }
                        cli_args->argc++;
                }
	}
	lua_pop(L, 1);
	return 0;
}

NO_SANITIZE static int
luaL_get_args_from_table(lua_State *L, luzer_args *table_args) {
        if (lua_istable(L, -1) == 0) {
                return -2;
        }

	lua_pushnil(L);

	/* Processing a table with options. */
	table_args->argc = 0;
        while (lua_next(L, -2) != 0) {
		const char *key = lua_tostring(L, -2);
		const char *value = lua_tostring(L, -1);
		lua_pop(L, 1);

                /* +1 for null terminated */
                size_t arg_len = FLAG_FULL_SIZE(key) + strlen(value) + 1;
		char *arg = calloc(arg_len, sizeof(char));
		if (!arg) {
                        return -1;
                }
		snprintf(arg, arg_len, FLAG_PATTERN_KEY_VALUE, key, value);

		if (table_args->argc > 0) {
                        if (add_arg_with_mem_allocation(table_args, arg)) {
                                return -1;
                        }
		} else {
			table_args->argv = malloc(1 * sizeof(char*));
			if (!table_args->argv) {
                                return -1;
                        }
                        table_args->argv[table_args->argc] = arg;
		}
		table_args->argc++;
	}
	lua_pop(L, 1);
	return 0;
}

NO_SANITIZE static int
merge_args(luzer_args *cli_args, luzer_args *table_args, luzer_args *total_args) {
	/* Program name is first argument. */
        total_args->argc = 1;
	total_args->argv = malloc(sizeof(char*));
	if (!cli_args->argv) {
                return -1;
        }

	/* Program name on zero index. */
	total_args->argv[0] = cli_args->argv[0];

	char *corpus_path = NULL;
	for (int i = 0; i < table_args->argc; i++) {
		if (strncmp(table_args->argv[i], SEED_CORPUS_PATH_FLAG, strlen(SEED_CORPUS_PATH_FLAG)) == 0) {
			int corpus_path_len = strlen(table_args->argv[i]) - strlen(SEED_CORPUS_PATH_FLAG);
			corpus_path = malloc(corpus_path_len * sizeof(char*));
                        if (!corpus_path) {
                                return -1;
                        }
			memcpy(corpus_path, &table_args->argv[i][strlen(SEED_CORPUS_PATH_FLAG) + 1], corpus_path_len);
			free(table_args->argv[i]);
                        table_args->argv[i] = NULL;
		} else {
                        char key[strlen(table_args->argv[i]) + 1];
                        if (sscanf(table_args->argv[i], FLAG_SCANF_FORMAT_KEY, key) == 0) {
#ifdef DEBUG
                                DEBUG_PRINT("error get libfuzzer flag in string: %s\n", table_args->argv[i]);
#endif /* DEBUG */
                                continue;
                        }

                        if (is_flag_in_args(cli_args, key)) {
                                continue;
                        }

                        if (add_arg_with_mem_allocation(total_args, table_args->argv[i])) {
                                return -1;
                        }
                        total_args->argc++;
		}
	}

	for (int i = 1; i < cli_args->argc; i++) {
                if (add_arg_with_mem_allocation(total_args, cli_args->argv[i])) {
                        return -1;
                }
		total_args->argc++;
	}
	if (corpus_path) {
                if (add_arg_with_mem_allocation(total_args, corpus_path)) {
                        return -1;
                }
		total_args->argc++;
	}

        if (add_arg_with_mem_allocation(total_args, NULL)) {
                return -1;
        }

        if (table_args->argv) {
                free(table_args->argv);
        }

        if (cli_args->argv) {
                free(cli_args->argv);
        }

	return 0;
}

NO_SANITIZE static void
free_args(luzer_args args) {
        if (!args.argv) {
                return;
        }
        for (int i = 0; i < args.argc; i++) {
                if (args.argv[i]) {
                        free(args.argv[i]);
                }
        }
        free(args.argv);
}

#ifdef DEBUG
NO_SANITIZE static void
print_args_with_prefix(luzer_args args, const char* prefix) {
        for (int i = 0; i < args.argc; i++) {
                DEBUG_PRINT("libFuzzer %s arg - '%s'\n", prefix, args.argv[i]);
        }
}
#endif /* DEBUG */

NO_SANITIZE int
luaL_get_fuzz_args(lua_State *L, char ***argv, int *argc) {
        luzer_args total_args = { .argv = NULL, .argc = 0};
        luzer_args cli_args = { .argv = NULL, .argc = 0 };
	luzer_args table_args = { .argv = NULL, .argc = 0 };

        int result = -1;
        result = luaL_get_args_from_cli(L, &cli_args);
        if (result != 0) {
                free_args(cli_args);
                luaL_error(L, "failed parsing fuzz args. not enough memory");
        }

#ifdef DEBUG
        print_args_with_prefix(cli_args, "from cli");
#endif /* DEBUG */

	/* If flag in cli and lua is duplicated, then flag from lua is ignored. */
	result = luaL_get_args_from_table(L, &table_args);
        if (result != 0) {
                free_args(table_args);
                free_args(cli_args);
                if (result == -2) {
                        luaL_error(L, "failed parsing fuzz args. last argument is not a table");
                }
                luaL_error(L, "failed parsing fuzz args. not enough memory");
        }

#ifdef DEBUG
        print_args_with_prefix(table_args, "from table");
#endif /* DEBUG */

	result = merge_args(&cli_args, &table_args, &total_args);
        if (result != 0) {
                free_args(table_args);
                free_args(cli_args);
                free_args(total_args);
                luaL_error(L, "failed parsing fuzz args. not enough memory");
        }

#ifdef DEBUG
        print_args_with_prefix(total_args, "total");
#endif /* DEBUG */

        *argv = total_args.argv;
        *argc = total_args.argc;

        return 0;
}
