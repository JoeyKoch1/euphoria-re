#ifndef EU_DB_H
#define EU_DB_H

#include "euphoria.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct EuDb EuDb;

EuDb *eu_db_create(void);
void eu_db_destroy(EuDb *db);
EuStatus eu_db_add_function(EuDb *db, EuFunction function);
const EuFunction *eu_db_functions(const EuDb *db, size_t *count);
EuStatus eu_db_save(const EuDb *db, const char *path);

#ifdef __cplusplus
}
#endif

#endif
