#ifndef EU_SCAN_H
#define EU_SCAN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Both scanners return len when there is no match.
size_t eu_scan_byte(const uint8_t *data, size_t len, uint8_t byte);
size_t eu_scan_byte_c(const uint8_t *data, size_t len, uint8_t byte);
size_t eu_scan_pattern(const uint8_t *data, size_t len, const uint8_t *pattern, size_t pattern_len);

#ifdef EU_HAVE_AVX2
size_t eu_scan_byte_avx2(const uint8_t *data, size_t len, uint8_t byte);
#endif

#ifdef __cplusplus
}
#endif

#endif
