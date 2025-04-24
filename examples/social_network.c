#include <stdio.h>
#include <signal.h>
#include "../tinyhttp.h"

/////////////////////////////////////////////////////////////////
// CONFIGURATION
/////////////////////////////////////////////////////////////////

// Network stuff
#define ADDR    "127.0.0.1"
#define PORT    8080
#define REUSE   1
#define BACKLOG 32

// Social stuff
#define MAX_USERS    32
#define MAX_POSTS    32
#define MAX_USERNAME 128
#define MAX_PASSWORD 256
#define MAX_BIO      512
#define MAX_CONTENT  512

/////////////////////////////////////////////////////////////////
// UTILITIES
/////////////////////////////////////////////////////////////////

typedef struct {
	char     *ptr;
	ptrdiff_t len;
} string;

#define S(X) ((string) {(X), sizeof(X)-1})

static string trim(string s)
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
		while (s.ptr[s.len-1] == ' ' || s.ptr[s.len-1] == '\n')
			s.len--;
	}

	return s;
}

static int copy(string src, string *dst, char *mem, int cap)
{
	if (src.len > cap)
		return -1;
	memcpy(mem, src.ptr, src.len);
	dst->ptr = mem;
	dst->len = src.len;
	return 0;
}

/////////////////////////////////////////////////////////////////
// BUSINESS LOGIC
/////////////////////////////////////////////////////////////////

typedef struct {
	string name;
	string pass;
	string bio;
	char name_mem[MAX_USERNAME];
	char pass_mem[MAX_PASSWORD];
	char bio_mem[MAX_BIO];
} User;

typedef struct {
	int id;
	string author;
	string content;
	char author_mem[MAX_USERNAME];
	char content_mem[MAX_CONTENT];
} Post;

static User users[MAX_USERS];
static int  user_count = 0;

static Post posts[MAX_POSTS];
static int  posts_head  = 0;
static int  posts_count = 0;

static void init_users_and_posts(void)
{
	// TODO
}

static int find_user(string name)
{
	for (int i = 0; i < user_count; i++)
		if (streq(name, users[i].name))
			return i;
	return -1;
}

static int create_user(string name, string pass)
{
	name = trim(name);
	pass = trim(pass);

	if (name.len == 0 || pass.len == 0)
		return -1;

	if (find_user(name) != -1)
		return -1;

	if (user_count == MAX_USERS)
		return -1;

	User *user = &users[user_count];

	if (copy(name, &user->name, user->name_mem, sizeof(user->name_mem)) < 0 &&
		copy(pass, &user->pass, user->pass_mem, sizeof(user->pass_mem)) < 0)
		return -1;

	user_count++;
	return 0;
}

static int delete_user(string name)
{
	int i = find_user(name);
	if (i == -1)
		return -1;

	// TODO
}

static int create_post(string author, string content)
{
	// TODO
}

static int delete_post(int id)
{
	// TODO
}

static int modify_post(int id, string new_content)
{
	// TODO
}

/////////////////////////////////////////////////////////////////
// ENDPOINTS
/////////////////////////////////////////////////////////////////

#define MAX_SESSIONS 32

typedef struct {
	int id;
	string name;
	char name_mem[MAX_USERNAME];
} Session;

static Session sessions[MAX_SESSIONS];
static int     session_count = 0;

static void init_sessions(void)
{
	for (int i = 0; i < MAX_SESSIONS; i++)
		sessions[i].id = -1;
}

static int find_session(int id)
{
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].id == id)
			return i;
	return -1;
}

static int create_session(string name)
{
	// TODO
}

static int delete_session(string name)
{
	// TODO
}

// TODO

/////////////////////////////////////////////////////////////////
// ENTRY POINT
/////////////////////////////////////////////////////////////////

static sig_atomic_t should_exit = 0;

static void
signal_handler(int sig)
{
	if (sig == SIGINT)
		should_exit = 1;
}

int main(void)
{
	signal(SIGINT, signal_handler);

	init_users_and_posts();
	init_sessions();

	TinyHTTPServerConfig config = {
		.reuse = REUSE,
		.plain_addr = ADDR,
		.plain_port = PORT,
		.plain_backlog = BACKLOG,
	};

	TinyHTTPServer *server = tinyhttp_server_init(config);
	if (server == NULL)
		return -1;

	while (!should_exit) {

		int ret;
		TinyHTTPRequest *req;
		TinyHTTPResponse res;

		ret = tinyhttp_server_wait(server, &req, &res, 1000);
		if (ret < 0) return -1; // Error
		if (ret > 0) continue; // Timeout

		char path_mem[1<<10];
		TinyHTTPString path;	
		if (tinyhttp_normalizepath(req->path, &path, path_mem, sizeof(path_mem)) < 0) {
			tinyhttp_response_status(res, 200);
			tinyhttp_response_send(res);
			continue;
		}

		TinyHTTPString sessid = tinyhttp_getcookie(req, TINYHTTP_STRING("sessid"));

		if (tinyhttp_streq(path, TINYHTTP_STRING("/users"))) {
			tinyhttp_response_status(res, 200);
			tinyhttp_response_body(res, "<html><head><title>Users</title></head><body><ul>", -1);
			for (int i = 0; i < user_count; i++)
				tinyhttp_response_body(res, "<li><a href=\"/users/???\">???</a></li>", -1);
			tinyhttp_response_body(res, "</ul></body></html>", -1);
			tinyhttp_response_send(res);
			continue;
		}

		if (tinyhttp_streq(path, TINYHTTP_STRING("/posts"))) {
			tinyhttp_response_status(res, 200);
			tinyhttp_response_body(res, "<html><head><title>Posts</title></head><body><ul>", -1);
			for (int i = 0; i < user_count; i++)
				tinyhttp_response_body(res, "<li><a href=\"/posts/???\">???</a></li>", -1);
			tinyhttp_response_body(res, "</ul></body></html>", -1);
			tinyhttp_response_send(res);
			continue;
		}

		tinyhttp_response_status(res, 404);
		tinyhttp_response_body(res, "<html><head><title>Not Found</title></head><body>Nothing here!</body></html>", -1);
		tinyhttp_response_send(res);
	}

	tinyhttp_server_free(server);
	return 0;
}
