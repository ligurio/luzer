#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	assert(Data);
	char *buf = calloc(Size, sizeof(char *));
	memcpy(buf, (char *)Data, Size);
	buf[Size] = '\0';
	if (strcmp((char *)buf, "A") == 0) {
		fprintf(stderr, "BINGO: Found the target, exiting.\n");
		_exit(1);
	}
	free(buf);
	return 0;
}
