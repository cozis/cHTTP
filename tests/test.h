#include <stdio.h>
#include "../tinyhttp.h"

#define S HTTP_STR

#define COUNT(X) (int) (sizeof(X)/sizeof((X)[0]))
#define TEST(X) {if (!(X)) { fprintf(stderr, "Failed test at %s:%d\n", __FILE__, __LINE__); __builtin_trap(); }}

void testeq_engstate(HTTP_EngineState l, HTTP_EngineState r, HTTP_String uneval_l, HTTP_String uneval_r, const char *file, int line);
void testeq_int(int l, int r, HTTP_String uneval_l, HTTP_String uneval_r, const char *file, int line);
void testeq_str(HTTP_String l, HTTP_String r, HTTP_String uneval_l, HTTP_String uneval_r, const char *file, int line);
#define TEST_EQ(X, Y) _Generic((X), HTTP_String: testeq_str, int: testeq_int, HTTP_EngineState: testeq_engstate)((X), (Y), S(#X), S(#Y), __FILE__, __LINE__)
