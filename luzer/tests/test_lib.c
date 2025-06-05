#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MESSAGE "Hello, Lua!"

int
say_hello(const char *buf) {
	if (strncmp(buf, MESSAGE, sizeof(MESSAGE)) == 0) {
		fprintf(stderr, "Hello, Lua!\n");
		abort();
	}
	return 0;
}
