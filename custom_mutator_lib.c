#include <stdio.h>
#include <stdint.h>

#include "macros.h"

size_t
LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
                        size_t max_size, unsigned int seed)
{
	printf("LLVMFuzzerCustomMutator\n");
	//return luaL_custom_mutator(L, data, size, max_size, seed);
	return 0;
}
