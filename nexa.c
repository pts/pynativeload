/*#include <stdio.h>*/
#include <stdarg.h>  /* TODO(pts): At least find this. */

int addmul32(int a, int b, int c, int d, int e, int f, int g, int h, int i) {
  return a * b + c * d + e * f + g * h + i;
}

long addmul(long a, long b, long c, long d, long e, long f, long g, long h, long i) {
  return a * b + c * d + e * f + g * h + i;
}

void xorp32(int *a, int *b) {
  *a ^= *b;
}

#if 0
int answer = 42;  /* .data */
int unknown;      /* .bss */
#endif

/*void _start() {}*/