// https://github.com/llvm/llvm-project/blob/f623dc9a8c37c3f2ed0a2138563a8b9e37adc1ce/compiler-rt/test/fuzzer/CustomMutatorTest.cpp
// https://github.com/llvm/llvm-project/blob/f623dc9a8c37c3f2ed0a2138563a8b9e37adc1ce/compiler-rt/test/fuzzer/CustomCrossOverTest.cpp


#include <assert.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <ostream>

// Simple test for a cutom crossover.
#include <assert.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <ostream>
#include <random>
#include <string.h>
#include <functional>

static volatile int Sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  assert(Data);
  if (Size > 0 && Data[0] == 'H') {
    Sink = 1;
    if (Size > 1 && Data[1] == 'i') {
      Sink = 2;
      if (Size > 2 && Data[2] == '!') {
        std::cout << "BINGO; Found the target, exiting\n" << std::flush;
        exit(1);
      }
    }
  }
  return 0;
}

static const char *Separator = "-########-";

/*
static const char *Target = "A-########-B";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  assert(Data);
  std::string Str(reinterpret_cast<const char *>(Data), Size);
  static const size_t TargetHash = std::hash<std::string>{}(std::string(Target));
  size_t StrHash = std::hash<std::string>{}(Str);

  // Ensure we have 'A' and 'B' in the corpus.
  if (Size == 1 && *Data == 'A')
    Sink++;
  if (Size == 1 && *Data == 'B')
    Sink--;

  if (TargetHash == StrHash) {
    std::cout << "BINGO; Found the target, exiting\n" << std::flush;
    exit(1);
  }
  return 0;
}
*/

extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t *Data1, size_t Size1,
                                            const uint8_t *Data2, size_t Size2,
                                            uint8_t *Out, size_t MaxOutSize,
                                            unsigned int Seed) {
  static size_t Printed;
  static size_t SeparatorLen = strlen(Separator);

  if (Printed++ < 32)
    std::cerr << "In LLVMFuzzerCustomCrossover " << Size1 << " " << Size2 << "\n";

  size_t Size = Size1 + Size2 + SeparatorLen;

  if (Size > MaxOutSize)
    return 0;

  memcpy(Out, Data1, Size1);
  memcpy(Out + Size1, Separator, SeparatorLen);
  memcpy(Out + Size1 + SeparatorLen, Data2, Size2);

  return Size;
}

#ifdef CUSTOM_MUTATOR

// Forward-declare the libFuzzer's mutator callback.
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

// The custom mutator:
//   * deserialize the data (in this case, uncompress).
//     * If the data doesn't deserialize, create a properly serialized dummy.
//   * Mutate the deserialized data.
//   * Serialize the mutated data (in this case, compress).
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  size_t CompressedLen = MaxSize;
  return CompressedLen;
}

#endif // CUSTOM_MUTATOR

#ifdef CUSTOM_MUTATOR_LUA

#include "libfuzzer_mutator.cpp"

#endif // CUSTOM_MUTATOR_LUA
