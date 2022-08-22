#include "FuzzedDataProvider.h"

void lua_consume_bool() {
	const uint8_t *data = {};
	size_t size = 1;
	FuzzedDataProvider* fdp = new FuzzedDataProvider(data, size);
	bool a = fdp->ConsumeBool();
	printf("%i\n", a);
}
