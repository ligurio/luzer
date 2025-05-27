#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MESSAGE "Lua"

int
say_hello(const char *buf) {
	if (strncmp(buf, MESSAGE, sizeof(MESSAGE)) == 0) {
		fprintf(stderr, "Hello, Lua!\n");
		abort();
	}

    return 1;
}
