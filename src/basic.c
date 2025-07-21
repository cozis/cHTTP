#include <stddef.h>
#include <string.h>

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#endif

bool http_streq(HTTP_String s1, HTTP_String s2)
{
	if (s1.len != s2.len)
		return false;

    for (int i = 0; i < s1.len; i++)
		if (s1.ptr[i] != s2.ptr[i])
			return false;

	return true;
}

static char to_lower(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	return c;
}

bool http_streqcase(HTTP_String s1, HTTP_String s2)
{
	if (s1.len != s2.len)
		return false;

	for (int i = 0; i < s1.len; i++)
		if (to_lower(s1.ptr[i]) != to_lower(s2.ptr[i]))
			return false;

	return true;
}

HTTP_String http_trim(HTTP_String s)
{
	int i = 0;
	while (i < s.len && (s.ptr[i] == ' ' || s.ptr[i] == '\t'))
		i++;

	if (i == s.len) {
		s.ptr = NULL;
		s.len = 0;
	} else {
		s.ptr += i;
		s.len -= i;
		while (s.ptr[s.len-1] == ' ' || s.ptr[s.len-1] == '\t')
			s.len--;
	}

	return s;
}

static bool is_printable(char c)
{
    return c >= ' ' && c <= '~';
}

#include <stdio.h>
void print_bytes(HTTP_String prefix, HTTP_String src)
{
    if (src.len == 0)
        return;

    FILE *stream = stdout;

    bool new_line = true;
    int cur = 0;
    for (;;) {
        int start = cur;

        while (cur < src.len && is_printable(src.ptr[cur]))
            cur++;

        if (new_line) {
            fwrite(prefix.ptr, 1, prefix.len, stream);
            new_line = false;
        }

        fwrite(src.ptr + start, 1, cur - start, stream);

        if (cur == src.len)
            break;

        if (src.ptr[cur] == '\n') {
            putc('\\', stream);
            putc('n',  stream);
            putc('\n', stream);
            new_line = true;
        } else if (src.ptr[cur] == '\r') {
            putc('\\', stream);
            putc('r',  stream);
        } else {
            putc('.', stream);
        }
        cur++;
    }
    putc('\n', stream);
}