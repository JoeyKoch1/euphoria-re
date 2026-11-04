#include "scan.h"

#include <string.h>

size_t eu_scan_byte_c(const uint8_t *data, size_t len, uint8_t byte) {
    const uint8_t *hit = len ? memchr(data, byte, len) : NULL;
    return hit ? (size_t)(hit - data) : len;
}

size_t eu_scan_byte(const uint8_t *data, size_t len, uint8_t byte) {
#ifdef EU_HAVE_AVX2
    if (__builtin_cpu_supports("avx2")) {
        return eu_scan_byte_avx2(data, len, byte);
    }
#endif
    return eu_scan_byte_c(data, len, byte);
}

size_t eu_scan_pattern(const uint8_t *data, size_t len, const uint8_t *pattern, size_t pattern_len) {
    if (pattern_len == 0 || pattern_len > len) {
        return len;
    }

    size_t last = len - pattern_len;
    size_t at = 0;
    while (at <= last) {
        at += eu_scan_byte(data + at, last + 1 - at, pattern[0]);
        if (at > last) {
            break;
        }
        if (memcmp(data + at, pattern, pattern_len) == 0) {
            return at;
        }
        at++;
    }
    return len;
}
