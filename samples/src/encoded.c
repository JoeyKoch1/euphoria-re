/*
 * Euphoria sample: strings hidden behind a single-byte XOR.
 *
 * The payload arrays live in .rdata and are rebuilt by `decode` at run time.
 * Open this file in Euphoria and use Advanced -> XOR to recover them, or
 * decompile `decode` to see the loop.
 *
 * Build from the repository root with:
 *     scripts/make-samples.sh
 *
 * It is intentionally harmless: it only prints text and exits.
 */
#include <stdio.h>

static const unsigned char payload[] = {
    0x0E, 0x32, 0x3F, 0x7A, 0x2A, 0x3B, 0x29, 0x29, 0x2D, 0x35, 0x28, 0x3E,
    0x7A, 0x33, 0x29, 0x7A, 0x3E, 0x3F, 0x39, 0x35, 0x3E, 0x3F, 0x3E, 0x7A,
    0x3C, 0x28, 0x35, 0x37, 0x7A, 0x2E, 0x32, 0x33, 0x29, 0x7A, 0x02, 0x15,
    0x08, 0x7A, 0x36, 0x35, 0x35, 0x2A, 0x7A, 0x3B, 0x2E, 0x7A, 0x28, 0x2F,
    0x34, 0x7A, 0x2E, 0x33, 0x37, 0x3F, 0x74,
};

static const unsigned char endpoint[] = {
    0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75, 0x29, 0x3B, 0x37, 0x2A,
    0x36, 0x3F, 0x29, 0x74, 0x3F, 0x2F, 0x2A, 0x32, 0x35, 0x28, 0x33, 0x3B,
    0x74, 0x33, 0x34, 0x2C, 0x3B, 0x36, 0x33, 0x3E, 0x75, 0x29, 0x2E, 0x3B,
    0x2E, 0x2F, 0x29,
};

static const unsigned char marker[] = {
    0x3E, 0x3F, 0x39, 0x35, 0x3E, 0x3F, 0x28, 0x77, 0x36, 0x35, 0x35, 0x2A,
};

/* The loop Euphoria should find: one XOR per byte. */
static void decode(char *out, const unsigned char *source, unsigned length) {
    unsigned char key = 0x5A;
    for (unsigned i = 0; i < length; i++) {
        out[i] = (char)(source[i] ^ key);
    }
    out[length] = '\0';
}

static unsigned checksum(const unsigned char *bytes, unsigned length) {
    unsigned total = 0;
    for (unsigned i = 0; i < length; i++) {
        total = (total * 31u) + bytes[i];
    }
    return total;
}

int main(void) {
    char message[sizeof payload + 1];
    char url[sizeof endpoint + 1];
    char name[sizeof marker + 1];

    decode(message, payload, (unsigned)sizeof payload);
    decode(url, endpoint, (unsigned)sizeof endpoint);
    decode(name, marker, (unsigned)sizeof marker);

    printf("[%s] %s\n", name, message);
    printf("endpoint: %s\n", url);
    printf("checksum: %08x\n", checksum(payload, (unsigned)sizeof payload));
    return checksum(payload, (unsigned)sizeof payload) == 0;
}
