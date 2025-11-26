
enum {

    HTTP_OK                = 0,

    // A generic error occurred
    HTTP_ERROR_UNSPECIFIED = -1,

    // Out of memory
    HTTP_ERROR_OOM         = -2,

    // Invalid URL
    HTTP_ERROR_BADURL      = -3,

    // Parallel request limit reached
    HTTP_ERROR_REQLIMIT    = -4,

    // Invalid handle
    HTTP_ERROR_BADHANDLE   = -5,

    // TLS support not built-in
    HTTP_ERROR_NOTLS       = -6,
};

// String type used throughout cHTTP.
typedef struct {
	char *ptr;
	int   len;
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

// Print the contents of a byte string with the given prefix.
// This is primarily used for debugging purposes.
void print_bytes(HTTP_String prefix, HTTP_String src);

// TODO: comment
char *http_strerror(int code);

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

// Macro to unpack an HTTP_String into its length and pointer components.
// Useful for passing HTTP_String to printf-style functions with "%.*s" format.
// Example: printf("%.*s", HTTP_UNPACK(str));
#define HTTP_UNPACK(X) (X).len, (X).ptr

// TODO: comment
#define HTTP_UNREACHABLE __builtin_trap()
