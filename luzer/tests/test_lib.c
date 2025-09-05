#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MESSAGE "Hello, Lua!"
#define OOB_SIZE 21
#define OOB_IDX 20
#define BUFFER_SIZE 20

char global_char_buffer[BUFFER_SIZE];
int global_array[BUFFER_SIZE];
char oob_value;

static int
test_heap_buffer_overflow(const char *buf, size_t len) {
	unsigned char *ptr = malloc(BUFFER_SIZE);
	ptr[OOB_IDX] = 0;
	return 0;
}

static int
test_dynamic_stack_buffer_overflow(const char *buf, size_t len) {
	char str[len];
	str[len] = 0;
	return 0;
}

#pragma clang diagnostic ignored "-Warray-bounds"
#pragma clang diagnostic push

static int
test_stack_buffer_overflow(const char *buf, size_t len) {
	char buffer[BUFFER_SIZE];
	oob_value = buffer[OOB_IDX];
	return 0;
}

static int
test_global_buffer_overflow(const char *buf, size_t len) {
	global_array[OOB_IDX] = 0;
	return 0;
}

#pragma clang diagnostic pop

#pragma clang diagnostic ignored "-Wfortify-source"
#pragma clang diagnostic push

static int
test_memset_buffer_overflow(const char *buf, size_t len) {
	memset(global_char_buffer, 0xAA, OOB_SIZE);
	return 0;
}

#pragma clang diagnostic pop

static int
test_memcpy_buffer_overflow(const char *buf, size_t len) {
	char buffer[OOB_SIZE];
	memcpy(buffer, global_char_buffer, OOB_SIZE);
	return 0;
}

static int
test_null_pointer_deref(const char *buf, size_t len) {
	const int *p1 = NULL;
	int p2 = *p1;
	(void)p2;
	return 0;
}

int
say_hello(const char *buf, size_t len) {
	if (strncmp(buf, MESSAGE, len) == 0) {
		fprintf(stderr, "%s\n", MESSAGE);
	}
	const char *mode = getenv("ERR_INJECTION");
	if (!mode)
		return 0;
	if (strcmp(mode, "HEAP_BUFFER_OVERFLOW") == 0) {
		test_heap_buffer_overflow(buf, len);
	} else if (strcmp(mode, "STACK_BUFFER_OVERFLOW") == 0) {
		test_stack_buffer_overflow(buf, len);
	} else if (strcmp(mode, "DYNAMIC_STACK_BUFFER_OVERFLOW") == 0) {
		test_dynamic_stack_buffer_overflow(buf, len);
	} else if (strcmp(mode, "GLOBAL_BUFFER_OVERFLOW") == 0) {
		test_global_buffer_overflow(buf, len);
	} else if (strcmp(mode, "MEMSET_BUFFER_OVERFLOW") == 0) {
		test_memset_buffer_overflow(buf, len);
	} else if (strcmp(mode, "MEMCPY_BUFFER_OVERFLOW") == 0) {
		test_memcpy_buffer_overflow(buf, len);
	} else if (strcmp(mode, "NULL_POINTER_DEREF") == 0) {
		test_null_pointer_deref(buf, len);
	}
	return 0;
}
