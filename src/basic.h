
enum {

    CHTTP_OK                = 0,

    // A generic error occurred
    CHTTP_ERROR_UNSPECIFIED = -1,

    // Out of memory
    CHTTP_ERROR_OOM         = -2,

    // Invalid URL
    CHTTP_ERROR_BADURL      = -3,

    // Parallel request limit reached
    CHTTP_ERROR_REQLIMIT    = -4,

    // Invalid handle
    CHTTP_ERROR_BADHANDLE   = -5,

    // TLS support not built-in
    CHTTP_ERROR_NOTLS       = -6,
};

// String type used throughout cHTTP.
typedef struct {
	char *ptr;
	int   len;
} CHTTP_String;

// Compare two strings and return true iff they have
// the same contents.
bool chttp_streq(CHTTP_String s1, CHTTP_String s2);

// Compre two strings case-insensitively (uppercase and
// lowercase versions of a letter are considered the same)
// and return true iff they have the same contents.
bool chttp_streqcase(CHTTP_String s1, CHTTP_String s2);

// Remove spaces and tabs from the start and the end of
// a string. This doesn't change the original string and
// the new one references the contents of the original one.
CHTTP_String chttp_trim(CHTTP_String s);

// Print the contents of a byte string with the given prefix.
// This is primarily used for debugging purposes.
void print_bytes(CHTTP_String prefix, CHTTP_String src);

// TODO: comment
char *chttp_strerror(int code);

// Macro to simplify converting string literals to
// CHTTP_String.
//
// Instead of doing this:
//
//   char *s = "some string";
//
// You do this:
//
//   CHTTP_String s = CHTTP_STR("some string")
//
// This is a bit cumbersome, but better than null-terminated
// strings, having a pointer and length variable pairs whenever
// a function operates on a string. If this wasn't a library
// I would have done for
//
//   #define S(X) ...
//
// But I don't want to cause collisions with user code.
#define CHTTP_STR(X) ((CHTTP_String) {(X), sizeof(X)-1})

// Returns the number of items of a static array.
#define CHTTP_COUNT(X) (int) (sizeof(X) / sizeof((X)[0]))

// Macro to unpack an CHTTP_String into its length and pointer components.
// Useful for passing CHTTP_String to printf-style functions with "%.*s" format.
// Example: printf("%.*s", CHTTP_UNPACK(str));
#define CHTTP_UNPACK(X) (X).len, (X).ptr

// TODO: comment
#define CHTTP_UNREACHABLE __builtin_trap()
