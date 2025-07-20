#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <http.h>

#define COUNT(X) (sizeof(X) / sizeof((X)[0]))

#define BLK "\e[0;30m"
#define RED "\e[0;31m"
#define GRN "\e[0;32m"
#define YEL "\e[0;33m"
#define BLU "\e[0;34m"
#define MAG "\e[0;35m"
#define CYN "\e[0;36m"
#define WHT "\e[0;37m"
#define RST "\e[0m"

HTTP_String *already_crawled = NULL;
int num_already_crawled = 0;
int cap_already_crawled = 0;

HTTP_String copystr(HTTP_String str)
{
    char *copy = malloc(str.len);
    if (copy == NULL)
        abort();
    memcpy(copy, str.ptr, str.len);
    return (HTTP_String) { copy, str.len };
}

int normalize_url(HTTP_String url, char *dst, int max)
{
    HTTP_URL parsed_url;
    if (http_parse_url(url.ptr, url.len, &parsed_url) <= 0)
        return -1;

    int len = snprintf(dst, max, "http://%.*s%.*s",
        (int) parsed_url.authority.host.text.len,
        parsed_url.authority.host.text.ptr,
        (int) parsed_url.path.len,
        parsed_url.path.ptr
    );
    if (len < 0 || len >= max)
        return -1;

    return len;
}

void add_to_crawled_list(HTTP_String url)
{
    if (num_already_crawled == cap_already_crawled) {

        int new_cap = 2 * cap_already_crawled;
        if (new_cap == 0)
            new_cap = 8;

        HTTP_String *new_ptr = malloc(new_cap * sizeof(HTTP_String));
        if (new_ptr == NULL)
            abort();

        if (cap_already_crawled > 0) {
            for (int i = 0; i < num_already_crawled; i++)
                new_ptr[i] = already_crawled[i];
            free(already_crawled);
        }

        already_crawled = new_ptr;
        cap_already_crawled = new_cap;
    }

    char buf[1<<10];
    int len = normalize_url(url, buf, (int) sizeof(buf));
    if (len < 0) return;

    already_crawled[num_already_crawled++] = copystr((HTTP_String) { buf, len });
}

bool is_already_crawled(HTTP_String url)
{
    char buf[1<<10];
    int len = normalize_url(url, buf, (int) sizeof(buf));
    if (len < 0 || len >= (int) sizeof(buf))
        return false;

    for (int i = 0; i < num_already_crawled; i++)
        if (http_streq(already_crawled[i], (HTTP_String) { buf, len }))
            return true;

    return false;
}

HTTP_String next_link(HTTP_String src, int *pcur)
{
    int cur = *pcur;

    for (;;) {

        while (cur < src.len && src.ptr[cur] != 'h')
            cur++;

        if (cur == src.len)
            break;

        int off = cur;

        HTTP_URL parsed_url;
        int len = http_parse_url(src.ptr + cur, src.len - cur, &parsed_url);
        if (len <= 0) {
            cur++;
            continue;
        }

        cur += len;

        if (!http_streq(parsed_url.scheme, HTTP_STR("http")) &&
            !http_streq(parsed_url.scheme, HTTP_STR("https")))
            continue;

        *pcur = cur;
        return (HTTP_String) { src.ptr + off, len };
    }

    *pcur = cur;
    return (HTTP_String) { NULL, 0 };
}

int main(int argc, char **argv)
{
    http_global_init();

    if (argc < 2) {
        printf("Usage: %s <URL>\n", argv[0]);
        return -1;
    }
    HTTP_String start_url = { argv[1], strlen(argv[1]) };

    HTTP_Client *client = http_client_init();
    if (client == NULL) {
        printf("Couldn't initialize HTTP client object\n");
        return -1;
    }

    HTTP_RequestHandle req;
    int ret = http_client_request(client, &req);
    if (ret < 0) {
        printf("Couldn't start request\n");
        http_client_free(client);
        return -1;
    }
    http_request_line(req, HTTP_METHOD_GET, start_url);
    http_request_header(req, "User-Agent: Simple crawler", -1);
    http_request_submit(req);

    for (;;) {

        HTTP_RequestHandle req;
        ret = http_client_wait(client, &req);
        if (ret < 0) {
            // TODO
            return -1;
        }

        HTTP_Response *res = http_request_result(req);
        if (res == NULL) {
            http_request_free(req);
            continue; // Request didn't complete
        }
        HTTP_String body = res->body;

        int cursor = 0;
        for (;;) {

            HTTP_String url = next_link(body, &cursor);
            if (url.len == 0) break;

            if (is_already_crawled(url)) {
                printf("Ignoring " RED "%.*s" RST "\n", (int) url.len, url.ptr);
                continue;
            }

            printf("Fetching " GRN "%.*s" RST "\n", (int) url.len, url.ptr);
            add_to_crawled_list(url);

            HTTP_RequestHandle req;
            ret = http_client_request(client, &req);
            if (ret < 0)
                continue;

            http_request_line(req, HTTP_METHOD_GET, url);
            http_request_header(req, "User-Agent: Simple crawler", -1);
            http_request_submit(req);
        }
    }

    http_client_free(client);
    http_global_free();
    return 0;
}
