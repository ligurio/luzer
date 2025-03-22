#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MESSAGE "Hello, Lua!"

int
say_hello(const char *buf, size_t len) {
	const char *mode = getenv("ERR_INJECTION");
	if (mode && strcmp(mode, "BUFFER_OVERFLOW") == 0) {
		char str[len];
		str[len] = 0;
	} else if (mode && strcmp(mode, "NULL_POINTER_DEREF") == 0) {
		const int *p1 = NULL;
		int p2 = *p1;
	}
	if (strncmp(buf, MESSAGE, len) == 0) {
		fprintf(stderr, "%s\n", MESSAGE);
	}
	return 0;
}
