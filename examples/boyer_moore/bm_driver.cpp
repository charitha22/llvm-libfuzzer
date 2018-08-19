#include <stdint.h>
#include <stddef.h>
#include "bm.h"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    bm_driver(data, size);
    return 0;
}
