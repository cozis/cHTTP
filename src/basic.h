#ifndef CHTTP_BASIC_INCLUDED
#define CHTTP_BASIC_INCLUDED

#include <stdbool.h>

// String type used throughout cHTTP.
typedef struct {
	char *ptr;
	long  len;
} HTTP_String;

// Compare two strings and return true iff they have
// the same contents.
bool http_streq(HTTP_String s1, HTTP_String s2);

// Compre two strings case-insensitively (uppercase and
// lowercase versions of a letter are considered the same)
// and return true iff they have the same contents.
bool http_streqcase(HTTP_String s1, HTTP_String s2);

// Remove spaces and tabs from the start and the end of
// a string. This doesn't change the original string and
// the new one references the contents of the original one.
HTTP_String http_trim(HTTP_String s);

// Macro to simplify converting string literals to
// HTTP_String.
//
// Instead of doing this:
//
//   char *s = "some string";
//
// You do this:
//
//   HTTP_String s = HTTP_STR("some string")
//
// This is a bit cumbersome, but better than null-terminated
// strings, having a pointer and length variable pairs whenever
// a function operates on a string. If this wasn't a library
// I would have done for
//
//   #define S(X) ...
//
// But I don't want to cause collisions with user code.
#define HTTP_STR(X) ((HTTP_String) {(X), sizeof(X)-1})

// Returns the number of items of a static array.
#define HTTP_COUNT(X) (sizeof(X) / sizeof((X)[0]))

// Macro used to make invariants of the code more explicit.
//
// Say you have some function that operates on two integers
// and that by design their sum is always 100. This macro is
// useful to make that explicit:
//
//   void func(int a, int b)
//   {
//     HTTP_ASSERT(a + b == 100);
//     ...
//   }
//
// Assertions are about documentation, *not* error management.
//
// In non-release builds (where NDEBUG is not defined) asserted
// expressions are evaluated and if not true, the program is halted.
// This is quite nice as they offer a way to document code in
// a way that can be checked at runtime, unlike regular comments
// like this one.
#ifdef NDEBUG
#define HTTP_ASSERT(X) ((void) 0)
#else
#define HTTP_ASSERT(X) {if (!(X)) { __builtin_trap(); }}
#endif

#endif // CHTTP_BASIC_INCLUDED