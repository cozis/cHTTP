#ifndef BASIC_INCLUDED
#define BASIC_INCLUDED
#define HTTP_STR(X) ((HTTP_String) {(X), sizeof(X)-1})
#define HTTP_CEIL(X, Y) (((X) + (Y) - 1) / (Y))

typedef struct {
	char *ptr;
	long  len;
} HTTP_String;

int         http_streq     (HTTP_String s1, HTTP_String s2);
int         http_streqcase (HTTP_String s1, HTTP_String s2);
HTTP_String http_trim      (HTTP_String s);

#define HTTP_COUNT(X) (sizeof(X) / sizeof((X)[0]))
#define HTTP_ASSERT(X) {if (!(X)) { __builtin_trap(); }}

#endif // BASIC_INCLUDED