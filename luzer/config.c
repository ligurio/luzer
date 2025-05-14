#include "macros.h"

NO_SANITIZE const char *
llvm_version_string(void) {
	return "@LLVM_VERSION@";
}

NO_SANITIZE const char *
luzer_version_string(void) {
	return "@CMAKE_PROJECT_VERSION@";
}
