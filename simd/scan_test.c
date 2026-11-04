#include "scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LEN 256

static int check(const uint8_t *data, size_t len, uint8_t byte) {
    size_t expected = eu_scan_byte_c(data, len, byte);
    if (eu_scan_byte(data, len, byte) != expected) {
        fprintf(stderr, "dispatch mismatch: len=%zu byte=%u\n", len, byte);
        return 1;
    }
#ifdef EU_HAVE_AVX2
    if (__builtin_cpu_supports("avx2") && eu_scan_byte_avx2(data, len, byte) != expected) {
        fprintf(stderr, "avx2 mismatch: len=%zu byte=%u\n", len, byte);
        return 1;
    }
#endif
    return 0;
}

int main(void) {
    uint8_t data[MAX_LEN];
    int failures = 0;

    for (size_t len = 0; len <= MAX_LEN; len++) {
        memset(data, 0, sizeof(data));
        failures += check(data, len, 0xCC);
        for (size_t at = 0; at < len; at++) {
            data[at] = 0xCC;
            failures += check(data, len, 0xCC);
            data[at] = 0;
        }
    }

    srand(1);
    for (int round = 0; round < 100000; round++) {
        size_t len = (size_t)rand() % (MAX_LEN + 1);
        for (size_t i = 0; i < len; i++) {
            data[i] = (uint8_t)(rand() & 0x0F);
        }
        failures += check(data, len, (uint8_t)(rand() & 0x0F));
    }

    const uint8_t pattern[] = {0x55, 0x48, 0x89, 0xE5};
    const uint8_t hay[] = {0x55, 0x48, 0x00, 0x55, 0x48, 0x89, 0xE5, 0x90};
    if (eu_scan_pattern(hay, sizeof(hay), pattern, sizeof(pattern)) != 3) {
        fprintf(stderr, "pattern mismatch\n");
        failures++;
    }
    if (eu_scan_pattern(hay, 6, pattern, sizeof(pattern)) != 6) {
        fprintf(stderr, "truncated pattern mismatch\n");
        failures++;
    }

    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
