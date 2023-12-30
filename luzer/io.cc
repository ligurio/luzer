/*
 * SPDX-License-Identifier: ISC
 *
 */
#include <vector>
#include <string>
#include <cstdint>
/**
 * Okay, we all know this is bad, but unless we want to include third-party
 * headers or libs to do crossplatform IO (damn Windows cannot into readdir)
 * we better use whatever libfuzzer... shyly gives to us with no guarantees.
 * Remember - those things do not have ATTRIBUTE_INTERFACE in LF's codebase.
 * Bu-u-u-ut libfuzzer is pretty much in maintenance mode so I think it's
 * safe.
 * What's worse than using non-public-API is using C++. But this project already
 * uses clang++ with 'fuzzed_data_provider.cc'. Hey, libfuzzer IS written in C++.
 */

extern "C" {
#include "macros.h"

	int map_over_dir_contents(char const *dirpath, int (*user_cb)(uint8_t const *data, size_t length));
}

/**
 * See link for source of this
 * https://github.com/llvm/llvm-project/blob/493cc71d72c471c841b490f30dd8f26f3a0d89de/compiler-rt/lib/fuzzer/FuzzerDefs.h#L41
 */
typedef std::vector<uint8_t> Unit;

/**
 * See link for source of this
 * https://github.com/llvm/llvm-project/blob/493cc71d72c471c841b490f30dd8f26f3a0d89de/compiler-rt/lib/fuzzer/FuzzerIO.cpp#L101
 */
namespace fuzzer {
	void ReadDirToVectorOfUnits(
		const char *Path,
		std::vector<Unit> *V, long *Epoch,
		size_t MaxSize,
		bool ExitOnError,
		std::vector<std::string> *VPaths);
	bool IsDirectory(const std::string &Path);
}

NO_SANITIZE int
map_over_dir_contents(char const *dirpath, int (*user_cb)(uint8_t const * data, size_t length))
{
	if (nullptr == user_cb || nullptr == dirpath) {
		return -1;
	}

	if (!fuzzer::IsDirectory(dirpath)) {
		return -2;
	}

	std::vector<Unit> seed_corpus;
	fuzzer::ReadDirToVectorOfUnits(
			dirpath,
		       	&seed_corpus,
		       	/*Epoch = */nullptr,
		       	/*MaxSize = */SIZE_MAX,
		       	/*ExitOnError = */false,
			/*VPaths = */nullptr
			);

	for (auto unit : seed_corpus) {
		user_cb(unit.data(), unit.size());
	}
	return 0;
}

