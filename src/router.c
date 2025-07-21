#include <string.h>
#include <stdlib.h>
#include <limits.h>

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "router.h"
#endif

#ifndef HTTP_AMALGAMATION
bool is_alpha(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
bool is_digit(char c)
{
	return c >= '0' && c <= '9';
}
#endif // HTTP_AMALGAMATION

typedef enum {
	ROUTE_STATIC_DIR,
	ROUTE_DYNAMIC,
} RouteType;

typedef struct {
	RouteType type;
	HTTP_String endpoint;
	HTTP_String path;
	HTTP_RouterFunc func;
	void *ptr;
} Route;

struct HTTP_Router {
	int num_routes;
	int max_routes;
	Route routes[];
};

HTTP_Router *http_router_init(void)
{
	int max_routes = 32;
	HTTP_Router *router = malloc(max_routes * sizeof(HTTP_Router));
	if (router == NULL)
		return NULL;
	router->max_routes = max_routes;
	router->num_routes = 0;
	return router;
}

void http_router_free(HTTP_Router *router)
{
	free(router);
}

void http_router_dir(HTTP_Router *router, HTTP_String endpoint, HTTP_String path)
{
	if (router->num_routes == router->max_routes)
		abort();
	Route *route = &router->routes[router->num_routes++];
	route->type = ROUTE_STATIC_DIR;
	route->endpoint = endpoint;
	route->path = path;
}

void http_router_func(HTTP_Router *router, HTTP_Method method,
	HTTP_String endpoint, HTTP_RouterFunc func, void *ptr)
{
	if (router->num_routes == router->max_routes)
		abort();
	Route *route = &router->routes[router->num_routes++];
	(void) method; // TODO: Don't ignore the method
	route->type = ROUTE_DYNAMIC;
	route->endpoint = endpoint;
	route->func = func;
	route->ptr  = ptr;
}

static int valid_component_char(char c)
{
	return is_alpha(c) || is_digit(c) || c == '-' || c == '_' || c == '.'; // TODO
}

static int parse_and_sanitize_path(HTTP_String path, HTTP_String *comps, int max_comps)
{
	// We treat relative and absolute paths the same
	if (path.len > 0 && path.ptr[0] == '/') {
		path.ptr++;
		path.len--;
		if (path.len == 0)
			return 0;
	}

	int num = 0;
	int cur = 0;
	for (;;) {
		if (cur == path.len || !valid_component_char(path.ptr[cur]))
			return -1; // Empty component
		int start = cur;
		do
			cur++;
		while (cur < path.len && valid_component_char(path.ptr[cur]));
		HTTP_String comp = { path.ptr + start, cur - start };

		if (http_streq(comp, HTTP_STR(".."))) {
			if (num == 0)
				return -1;
			num--;
		} else if (!http_streq(comp, HTTP_STR("."))) {
			if (num == max_comps)
				return -1;
			comps[num++] = comp;
		}

		if (cur < path.len) {
			if (path.ptr[cur] != '/')
				return -1;
			cur++;
		}

		if (cur == path.len)
			break;
	}

	return num;
}

static int
serialize_parsed_path(HTTP_String *comps, int num_comps, char *dst, int max)
{
	int len = 0;
	for (int i = 0; i < num_comps; i++)
		len += comps[i].len + 1;

	if (len >= max)
		return -1;

	int copied = 0;
	for (int i = 0; i < num_comps; i++) {

		if (i > 0)
			dst[copied++] = '/';

		memcpy(dst + copied,
			comps[i].ptr,
			comps[i].len);

		copied += comps[i].len;
	}

	dst[copied] = '\0';
	return copied;
}

#define MAX_COMPS 32

static int sanitize_path(HTTP_String path, char *dst, int max)
{
	HTTP_String comps[MAX_COMPS];
	int num_comps = parse_and_sanitize_path(path, comps, MAX_COMPS);
	if (num_comps < 0) return -1;

	return serialize_parsed_path(comps, num_comps, dst, max);
}

static int swap_parents(HTTP_String original_parent_path, HTTP_String new_parent_path, HTTP_String path, char *mem, int max)
{
	int num_original_parent_path_comps;
	HTTP_String  original_parent_path_comps[MAX_COMPS];

	int num_new_parent_path_comps;
	HTTP_String  new_parent_path_comps[MAX_COMPS];

	int num_path_comps;
	HTTP_String  path_comps[MAX_COMPS];

	num_original_parent_path_comps = parse_and_sanitize_path(original_parent_path, original_parent_path_comps, MAX_COMPS);
	num_new_parent_path_comps      = parse_and_sanitize_path(new_parent_path,      new_parent_path_comps,      MAX_COMPS);
	num_path_comps                 = parse_and_sanitize_path(path,                 path_comps,                 MAX_COMPS);
	if (num_original_parent_path_comps < 0 || num_new_parent_path_comps < 0 || num_path_comps < 0)
		return -1;

	int match = 1;
	if (num_path_comps < num_original_parent_path_comps)
		match = 0;
	else {
		for (int i = 0; i < num_original_parent_path_comps; i++)
			if (!http_streq(original_parent_path_comps[i], path_comps[i])) {
				match = 0;
				break;
			}
	}
	if (!match)
		return 0;

	int num_result_comps = num_new_parent_path_comps + num_path_comps - num_original_parent_path_comps;
	if (num_result_comps < 0 || num_result_comps > MAX_COMPS)
		return -1;
	
	HTTP_String result_comps[MAX_COMPS];
	for (int i = 0; i < num_new_parent_path_comps; i++)
		result_comps[i] = new_parent_path_comps[i];
	
	for (int i = 0; i < num_path_comps; i++)
		result_comps[num_new_parent_path_comps + i] = path_comps[num_original_parent_path_comps + i];

	return serialize_parsed_path(result_comps, num_result_comps, mem, max);
}

#if _WIN32
typedef HANDLE File;
#else
typedef int File;
#endif

static int file_open(const char *path, File *handle, int *size)
{
#ifdef _WIN32
	*handle = CreateFileA(
		path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (*handle == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		if (error == ERROR_FILE_NOT_FOUND)
			return 1;
		if (error == ERROR_ACCESS_DENIED)
			return 1;
		return -1;
	}
	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(*handle, &fileSize)) {
		CloseHandle(*handle);
		return -1;
	}
	if (fileSize.QuadPart > INT_MAX) {
		CloseHandle(*handle);
		return -1;
	}
	*size = (int) fileSize.QuadPart;
	return 0;
#else
	*handle = open(path, O_RDONLY);
	if (*handle < 0) {
		if (errno == ENOENT)
			return 1;
		return -1;
	}
	struct stat info;
	if (fstat(*handle, &info) < 0) {
		close(*handle);
		return -1;
	}
	if (S_ISDIR(info.st_mode)) {
		close(*handle);
		return 1;
	}
	if (info.st_size > INT_MAX) {
		close(*handle);
		return -1;
	}
	*size = (int) info.st_size;
	return 0;
#endif
}

static void file_close(File file)
{
#ifdef _WIN32
	CloseHandle(file);
#else
	close(file);
#endif
}

static int file_read(File file, char *dst, int max)
{
#ifdef _WIN32
	DWORD num;
	BOOL ok = ReadFile(file, dst, max, &num, NULL);
	if (!ok)
		return -1;
	return (int) num;
#else
	return read(file, dst, max);
#endif
}

static int serve_file_or_index(HTTP_ResponseHandle res, HTTP_String base_endpoint, HTTP_String base_path, HTTP_String endpoint)
{
	char mem[1<<12];
	int ret = swap_parents(base_endpoint, base_path, endpoint, mem, sizeof(mem));
	if (ret <= 0)
		return ret;
	HTTP_String path = {mem, ret}; // Note that this is zero terminated

	int size;
	File file;
	ret = file_open(path.ptr, &file, &size);
	if (ret == -1) {
		http_response_status(res, 500);
		http_response_done(res);
		return 1;
	}
	if (ret == 1) {

		// File missing

		char index[] = "index.html";
		if (path.len + sizeof(index) + 1 > sizeof(mem)) {
			http_response_status(res, 500);
			http_response_done(res);
			return 1;
		}
		path.ptr[path.len++] = '/';
		memcpy(path.ptr + path.len, index, sizeof(index));
		path.len += sizeof(index)-1;

		ret = file_open(path.ptr, &file, &size);
		if (ret == -1) {
			http_response_status(res, 500);
			http_response_done(res);
			return 1;
		}
		if (ret == 1)
			return 0; // File missing
	}
	HTTP_ASSERT(ret == 0);

	int cap;
	char *dst;
	http_response_status(res, 200);
	http_response_bodycap(res, size);
	dst = http_response_bodybuf(res, &cap);
	if (dst) {
		int copied = 0;
		while (copied < size) {
			int ret = file_read(file, dst + copied, size - copied);
			if (ret < 0) goto err;
			if (ret == 0) break;
			copied += ret;
		}
		if (copied < size) goto err;
		http_response_bodyack(res, size);
	}
	http_response_done(res);
	file_close(file);
	return 1;
err:
	http_response_bodyack(res, 0);
	http_response_undo(res);
	http_response_status(res, 500);
	http_response_done(res);
	file_close(file);
	return 1;
}

static int serve_dynamic_route(Route *route, HTTP_Request *req, HTTP_ResponseHandle res)
{
	char path_mem[1<<12];
	int path_len = sanitize_path(req->url.path, path_mem, (int) sizeof(path_mem));
	if (path_len < 0) {
		http_response_status(res, 400);
		http_response_body(res, HTTP_STR("Invalid path"));
		http_response_done(res);
		return 1;
	}
	HTTP_String path = {path_mem, path_len};

	if (!http_streq(path, route->endpoint))
		return 0;

	route->func(req, res, route->ptr);
	return 1;
}

void http_router_resolve(HTTP_Router *router, HTTP_Request *req, HTTP_ResponseHandle res)
{
	for (int i = 0; i < router->num_routes; i++) {
		Route *route = &router->routes[i];
		switch (route->type) {
		case ROUTE_STATIC_DIR:
			if (serve_file_or_index(res,
				route->endpoint,
				route->path,
				req->url.path))
				return;
			break;

		case ROUTE_DYNAMIC:
			if (serve_dynamic_route(route, req, res))
				return;
			break;

		default:
			http_response_status(res, 500);
			http_response_done(res);
			return;
		}
	}
	http_response_status(res, 404);
	http_response_done(res);
}

int http_serve(char *addr, int port, HTTP_Router *router)
{
	int ret;

	HTTP_Server *server = http_server_init_ex((HTTP_String) { addr, strlen(addr) }, port, 0, (HTTP_String) {}, (HTTP_String) {});
	if (server == NULL) {
		http_router_free(router);
		return -1;
	}

	for (;;) {
		HTTP_Request *req;
		HTTP_ResponseHandle res;
		ret = http_server_wait(server, &req, &res);
		if (ret < 0) {
			http_server_free(server);
			http_router_free(router);
			return -1;
		}
		if (ret == 0)
			continue;
		http_router_resolve(router, req, res);
	}

	http_server_free(server);
	http_router_free(router);
	return 0;
}