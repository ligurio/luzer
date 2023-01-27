#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

#ifdef __cplusplus
extern "C" {
#endif

size_t
LLVMFuzzerCustomCrossOver(const uint8_t *Data1, size_t Size1,
						  const uint8_t *Data2, size_t Size2,
						  uint8_t *Out, size_t MaxOutSize,
						  unsigned int Seed);

#ifdef __cplusplus
} /* extern "C" */
#endif

static void
test_seed()
{
	time_t t;
	srand((unsigned) time(&t));

    uint8_t data[] = { 'L', 'U', 'A' };
	size_t size = COUNT_OF(data);
	size_t max_size = size;
	size_t seed = rand();
	size_t res = LLVMFuzzerCustomCrossOver(data, size, data, size,
										   NULL, max_size, seed);
	assert(res != 0);
}

int
main(void)
{
	test_seed();
}
