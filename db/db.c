#include "db.h"

#include <stdio.h>

static const char MAGIC[4] = {'E', 'U', 'D', 'B'};

struct EuDb {
    EuFunction *functions;
    size_t count;
    size_t capacity;
};

EuDb *eu_db_create(void) {
    return calloc(1, sizeof(EuDb));
}

void eu_db_destroy(EuDb *db) {
    if (db) {
        free(db->functions);
        free(db);
    }
}

EuStatus eu_db_add_function(EuDb *db, EuFunction function) {
    if (db->count == db->capacity) {
        size_t capacity = db->capacity ? db->capacity * 2 : 256;
        EuFunction *grown = realloc(db->functions, capacity * sizeof(EuFunction));
        if (!grown) {
            return EU_STATUS_OUT_OF_MEMORY;
        }
        db->functions = grown;
        db->capacity = capacity;
    }
    db->functions[db->count++] = function;
    return EU_STATUS_OK;
}

const EuFunction *eu_db_functions(const EuDb *db, size_t *count) {
    *count = db->count;
    return db->functions;
}

EuStatus eu_db_save(const EuDb *db, const char *path) {
    FILE *file = fopen(path, "wb");
    if (!file) {
        return EU_STATUS_IO;
    }

    uint32_t version = EU_ABI_VERSION;
    uint64_t count = db->count;
    int ok = fwrite(MAGIC, sizeof(MAGIC), 1, file) == 1
          && fwrite(&version, sizeof(version), 1, file) == 1
          && fwrite(&count, sizeof(count), 1, file) == 1
          && fwrite(db->functions, sizeof(EuFunction), db->count, file) == db->count;

    if (fclose(file) != 0 || !ok) {
        return EU_STATUS_IO;
    }
    return EU_STATUS_OK;
}
