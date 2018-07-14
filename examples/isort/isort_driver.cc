#include <stdint.h>
#include <stddef.h>
#include "isort.h"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    isort_driver(data, size);
    return 0;
}
