/*
 * Euphoria sample: a small native program.
 *
 * Build from the repository root with:
 *     scripts/make-samples.sh
 *
 * It is intentionally harmless: it only prints text and exits.
 */
#include <stdio.h>
#include <string.h>

static const char *BANNER = "Euphoria sample binary";
static const char *ENDPOINT = "https://samples.euphoria.invalid/hello";

/* A tiny routine that the decompiler can lift without surprises. */
static int weighted_sum(const int *values, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) {
        total += values[i] * (i + 1);
    }
    return total;
}

static void greet(const char *name) {
    printf("Hello, %s.\n", name);
}

int main(int argc, char **argv) {
    const int values[5] = {3, 1, 4, 1, 5};
    const char *name = argc > 1 ? argv[1] : "analyst";

    printf("%s\n", BANNER);
    greet(name);
    printf("weighted sum: %d\n", weighted_sum(values, 5));
    printf("endpoint: %s\n", ENDPOINT);
    printf("length: %zu\n", strlen(BANNER));
    return 0;
}
