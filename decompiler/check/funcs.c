// Pure integer routines used to compare the decompiler's output with the original machine code.
#define NI __attribute__((noinline))
#include <stdint.h>

NI int f_add(int a, int b) { return a + b * 3 - 7; }
NI int f_abs(int a) { return a < 0 ? -a : a; }
NI int f_max3(int a, int b, int c) { int m = a; if (b > m) m = b; if (c > m) m = c; return m; }
NI int f_sum(int n) { int t = 0; for (int i = 0; i < n; i++) t += i; return t; }
NI int f_classify(int value) {
    int total = 0;
    for (int i = 0; i < value; i++) {
        if (i % 3 == 0) total += i; else total ^= i;
    }
    return total;
}
NI int f_collatz(int n) { int s = 0; while (n > 1 && s < 1000) { n = (n & 1) ? 3 * n + 1 : n / 2; s++; } return s; }
NI int f_gcd(int a, int b) { while (b != 0) { int t = a % b; a = b; b = t; } return a; }
NI unsigned f_udiv(unsigned a) { return a / 10 + a % 7; }
NI int f_sdiv(int a) { return a / 5 - a % 9; }
NI int f_switch(int a) {
    switch (a) {
    case 0: return 11;
    case 1: return 22;
    case 2: return 37;
    case 3: return 41;
    case 4: return 59;
    case 5: return 63;
    case 6: return 71;
    default: return -1;
    }
}
NI int f_range(int a) { if (a >= 10 && a < 20) return 1; if (a == 5 || a == 7) return 2; return 3; }
NI int f_nested(int a, int b) {
    int r = 0;
    for (int i = 0; i < a; i++) {
        for (int j = 0; j < b; j++) {
            if (j > i) break;
            r += i * j;
        }
    }
    return r;
}
NI unsigned f_bits(unsigned x) { unsigned c = 0; while (x) { c += x & 1; x >>= 1; } return c; }
NI int8_t f_narrow(int8_t a, int8_t b) { return (int8_t)(a + b); }
NI int64_t f_wide(int64_t a, int b) { return a * 3 + b; }
NI int f_early(int a, int b) { if (a == 0) return b; if (b == 0) return a; return a * b; }
NI int f_dowhile(int a) { int c = 0; do { c += 2; a -= 3; } while (a > 0); return c; }
NI int f_cont(int n) { int s = 0; for (int i = 0; i < n; i++) { if (i & 1) continue; s += i; } return s; }
NI int f_callee(int x) { return f_add(x, 2) + f_abs(x); }
NI int f_many(int a, int b, int c, int d, int e, int f) { return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f; }
NI int f_callmany(int a) { return f_many(a, a + 1, a + 2, a + 3, a + 4, a + 5) - 1; }
NI int f_ptr(int *p, int n) { int s = 0; for (int i = 0; i < n; i++) s += p[i]; return s; }
NI void f_fill(int *p, int n, int v) { for (int i = 0; i < n; i++) p[i] = v + i; }
NI int f_local(int a) { int arr[4]; f_fill(arr, 4, a); return f_ptr(arr, 4); }
NI int f_strlen(const char *s) { int n = 0; while (*s++) n++; return n; }
