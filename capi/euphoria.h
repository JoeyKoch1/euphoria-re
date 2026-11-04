#ifndef EUPHORIA_H
#define EUPHORIA_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define EU_ABI_VERSION 1

typedef enum EuStatus {
  EU_STATUS_OK,
  EU_STATUS_INVALID_ARGUMENT,
  EU_STATUS_OUT_OF_MEMORY,
  EU_STATUS_IO,
  EU_STATUS_INTERNAL,
} EuStatus;

typedef enum EuArch {
  EU_ARCH_X86_64,
  EU_ARCH_AARCH64,
  EU_ARCH_X86,
} EuArch;

typedef struct EuSession EuSession;

typedef struct EuSection {
  uint64_t va;
  uint64_t offset;
  uint64_t size;
  bool executable;
} EuSection;

typedef struct EuImage {
  enum EuArch arch;
  uint64_t entry;
  const uint8_t *data;
  size_t data_len;
  const struct EuSection *sections;
  size_t section_count;
  const uint64_t *seeds;
  size_t seed_count;
} EuImage;

typedef struct EuFunction {
  uint64_t va;
  uint64_t size;
} EuFunction;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

extern enum EuStatus eu_session_analyze(const struct EuImage *image, struct EuSession **out);

extern const struct EuFunction *eu_session_functions(const struct EuSession *session,
                                                     size_t *count);

extern enum EuStatus eu_session_save(const struct EuSession *session, const char *path);

extern void eu_session_free(struct EuSession *session);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* EUPHORIA_H */
