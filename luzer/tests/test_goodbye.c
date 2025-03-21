#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MESSAGE "Goodbye, Lua!"

int
say_goodbye(const char *buf) {
	if (strncmp(buf, MESSAGE, sizeof(MESSAGE)) == 0) {
		fprintf(stderr, "Crash!\n");
		abort();
	}

    return 1;
}
