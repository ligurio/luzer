#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MESSAGE "Hello, Lua!"

int
say_hello(const char *buf, size_t len) {
	if (strncmp(buf, MESSAGE, len) == 0) {
		fprintf(stderr, "Hello, Lua!\n");
		abort();
	}
	return 0;
}
