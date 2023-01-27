#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

#ifdef __cplusplus
extern "C" {
#endif

size_t
LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
					    size_t MaxSize, unsigned int Seed);

#ifdef __cplusplus
} /* extern "C" */
#endif

static void
test_basic()
{
    uint8_t data[] = { 'L', 'U', 'A' };
	size_t size = COUNT_OF(data);
	size_t max_size = size + 1;
	size_t seed = 0;
	size_t res = LLVMFuzzerCustomMutator(data, size, max_size, seed);
	assert(res != 0);
	data[res] = '\0';
	assert(strcmp((char *)data, "XUA") == 0);
}

int
main(void)
{
	test_basic();
}
