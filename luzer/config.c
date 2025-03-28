#include "macros.h"

NO_SANITIZE const char *
llvm_version_string(void) {
	return "@LLVM_VERSION@";
}

NO_SANITIZE const char *
luzer_version_string(void) {
	return "@CMAKE_PROJECT_VERSION@";
}

NO_SANITIZE const char *
dso_asan_string(void) {
	return "@ASAN_DSO@";
}

NO_SANITIZE const char *
dso_ubsan_string(void) {
	return "@UBSAN_DSO@";
}
