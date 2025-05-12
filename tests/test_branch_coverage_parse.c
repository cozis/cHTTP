#include <stdlib.h>
#include <string.h>
#include "test.h"

static void test_branch_coverage_parse_request(void)
{
	struct {
		int line;
		int ret;
		char *str;
	} error_reqs[] = {
		{ __LINE__, -1, "G * HTTP/1.1\r\n\r\n"     },
		{ __LINE__, -1, "G@ * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "GE * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "GE@ * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, 18, "GET * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "GET@ * HTTP/1.1\r\n\r\n"  },

		{ __LINE__, -1, "P * HTTP/1.1\r\n\r\n"     },
		{ __LINE__, -1, "P@ * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "PO * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "PO@ * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "POS * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "POS@ * HTTP/1.1\r\n\r\n"  },
		{ __LINE__, 19, "POST * HTTP/1.1\r\n\r\n"  },
		{ __LINE__, -1, "POST@ * HTTP/1.1\r\n\r\n" },

		{ __LINE__, -1, "PU * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "PU@ * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, 18, "PUT * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "PUT@ * HTTP/1.1\r\n\r\n"  },

		{ __LINE__, -1, "H * HTTP/1.1\r\n\r\n"     },
		{ __LINE__, -1, "H@ * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "HE * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "HE@ * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "HEA * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "HEA@ * HTTP/1.1\r\n\r\n"  },
		{ __LINE__, 19, "HEAD * HTTP/1.1\r\n\r\n"  },
		{ __LINE__, -1, "HEAD@ * HTTP/1.1\r\n\r\n" },

		{ __LINE__, -1, "D * HTTP/1.1\r\n\r\n"       },
		{ __LINE__, -1, "D@ * HTTP/1.1\r\n\r\n"      },
		{ __LINE__, -1, "DE * HTTP/1.1\r\n\r\n"      },
		{ __LINE__, -1, "DE@ * HTTP/1.1\r\n\r\n"     },
		{ __LINE__, -1, "DEL * HTTP/1.1\r\n\r\n"     },
		{ __LINE__, -1, "DEL@ * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "DELE * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "DELE@ * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "DELET * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "DELET@ * HTTP/1.1\r\n\r\n"  },
		{ __LINE__, 21, "DELETE * HTTP/1.1\r\n\r\n"  },
		{ __LINE__, -1, "DELETE@ * HTTP/1.1\r\n\r\n" },

		{ __LINE__, -1, "C * HTTP/1.1\r\n\r\n"        },
		{ __LINE__, -1, "C@ * HTTP/1.1\r\n\r\n"       },
		{ __LINE__, -1, "CO * HTTP/1.1\r\n\r\n"       },
		{ __LINE__, -1, "CO@ * HTTP/1.1\r\n\r\n"      },
		{ __LINE__, -1, "CON * HTTP/1.1\r\n\r\n"      },
		{ __LINE__, -1, "CON@ * HTTP/1.1\r\n\r\n"     },
		{ __LINE__, -1, "CONN * HTTP/1.1\r\n\r\n"     },
		{ __LINE__, -1, "CONN@ * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "CONNE * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "CONNE@ * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "CONNEC * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "CONNEC@ * HTTP/1.1\r\n\r\n"  },
		{ __LINE__, 22, "CONNECT * HTTP/1.1\r\n\r\n"  },
		{ __LINE__, -1, "CONNECT@ * HTTP/1.1\r\n\r\n" },

		{ __LINE__, -1, "O * HTTP/1.1\r\n\r\n"        },
		{ __LINE__, -1, "O@ * HTTP/1.1\r\n\r\n"       },
		{ __LINE__, -1, "PO * HTTP/1.1\r\n\r\n"       },
		{ __LINE__, -1, "PO@ * HTTP/1.1\r\n\r\n"      },
		{ __LINE__, -1, "OPT * HTTP/1.1\r\n\r\n"      },
		{ __LINE__, -1, "OPT@ * HTTP/1.1\r\n\r\n"     },
		{ __LINE__, -1, "OPTI * HTTP/1.1\r\n\r\n"     },
		{ __LINE__, -1, "OPTI@ * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "OPTIO * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "OPTIO@ * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "OPTION * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "OPTION@ * HTTP/1.1\r\n\r\n"  },
		{ __LINE__, 22, "OPTIONS * HTTP/1.1\r\n\r\n"  },
		{ __LINE__, -1, "OPTIONS@ * HTTP/1.1\r\n\r\n" },

		{ __LINE__, -1, "T * HTTP/1.1\r\n\r\n"      },
		{ __LINE__, -1, "T@ * HTTP/1.1\r\n\r\n"     },
		{ __LINE__, -1, "TR * HTTP/1.1\r\n\r\n"     },
		{ __LINE__, -1, "TR@ * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "TRA * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "TRA@ * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "TRAC * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "TRAC@ * HTTP/1.1\r\n\r\n"  },
		{ __LINE__, 20, "TRACE * HTTP/1.1\r\n\r\n"  },
		{ __LINE__, -1, "TRACE@ * HTTP/1.1\r\n\r\n" },

		{ __LINE__, -1, "P * HTTP/1.1\r\n\r\n"      },
		{ __LINE__, -1, "P@ * HTTP/1.1\r\n\r\n"     },
		{ __LINE__, -1, "PA * HTTP/1.1\r\n\r\n"     },
		{ __LINE__, -1, "PA@ * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "PAT * HTTP/1.1\r\n\r\n"    },
		{ __LINE__, -1, "PAT@ * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "PATC * HTTP/1.1\r\n\r\n"   },
		{ __LINE__, -1, "PATC@ * HTTP/1.1\r\n\r\n"  },
		{ __LINE__, 20, "PATCH * HTTP/1.1\r\n\r\n"  },
		{ __LINE__, -1, "PATCH@ * HTTP/1.1\r\n\r\n" },

		{ __LINE__, -1, "GET *@\r\n\r\n" },
		{ __LINE__, -1, "GET * @\r\n\r\n" },
		{ __LINE__, -1, "GET * H\r\n\r\n" },
		{ __LINE__, -1, "GET * H@\r\n\r\n" },
		{ __LINE__, -1, "GET * HT\r\n\r\n" },
		{ __LINE__, -1, "GET * HT@\r\n\r\n" },
		{ __LINE__, -1, "GET * HTT\r\n\r\n" },
		{ __LINE__, -1, "GET * HTT@\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP@\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP/\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP/@\r\n\r\n" },
		{ __LINE__, 16, "GET * HTTP/1\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP/1@\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP/1.\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP/1.@\r\n\r\n" },
		{ __LINE__, 18, "GET * HTTP/1.1\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP/1.1@\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP/1.1@\nname:\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP/1.1\r@name:\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP/1.1\r\n@\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP/1.1\r\nn@\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP/1.1\r\nname\r\n\r\n" },
		{ __LINE__, 25, "GET * HTTP/1.1\r\nname:\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP/1.1\r\nname:\x1B\r\n\r\n" },
		{ __LINE__, 30, "GET * HTTP/1.1\r\nname:value\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP/1.1\r\nname  :value\r\n\r\n" },
		{ __LINE__, -1, "GET * HTTP/1.1\r\nname:val\rue\r\n\r\n" },

		{ __LINE__, 0, NULL },
	};

	for (int i = 0; error_reqs[i].str; i++) {
		HTTP_Request req;
		int ret = http_parse_request(error_reqs[i].str, strlen(error_reqs[i].str), &req);
		if (ret != error_reqs[i].ret) {
			fprintf(stderr, "Failed test at %s:%d (ret=%d, expected=%d)\n", __FILE__, error_reqs[i].line, ret, error_reqs[i].ret);
		}
	}

	{
		char str[] = "GET * HTTP/1.1\r\n\r\n";
		HTTP_Request req;
		int ret = http_parse_request(str, sizeof(str)-1, &req);
		TEST(ret == 18);
		TEST(req.method == HTTP_METHOD_GET);
	}

	{
		char str[] = "POST * HTTP/1.1\r\n\r\n";
		HTTP_Request req;
		int ret = http_parse_request(str, sizeof(str)-1, &req);
		TEST(ret == 19);
		TEST(req.method == HTTP_METHOD_POST);
	}

	{
		char str[] = "PUT * HTTP/1.1\r\n\r\n";
		HTTP_Request req;
		int ret = http_parse_request(str, sizeof(str)-1, &req);
		TEST(ret == 18);
		TEST(req.method == HTTP_METHOD_PUT);
	}

	{
		char str[] = "HEAD * HTTP/1.1\r\n\r\n";
		HTTP_Request req;
		int ret = http_parse_request(str, sizeof(str)-1, &req);
		TEST(ret == 19);
		TEST(req.method == HTTP_METHOD_HEAD);
	}

	{
		char str[] = "DELETE * HTTP/1.1\r\n\r\n";
		HTTP_Request req;
		int ret = http_parse_request(str, sizeof(str)-1, &req);
		TEST(ret == 21);
		TEST(req.method == HTTP_METHOD_DELETE);
	}

	{
		char str[] = "CONNECT * HTTP/1.1\r\n\r\n";
		HTTP_Request req;
		int ret = http_parse_request(str, sizeof(str)-1, &req);
		TEST(ret == 22);
		TEST(req.method == HTTP_METHOD_CONNECT);
	}

	{
		char str[] = "OPTIONS * HTTP/1.1\r\n\r\n";
		HTTP_Request req;
		int ret = http_parse_request(str, sizeof(str)-1, &req);
		TEST(ret == 22);
		TEST(req.method == HTTP_METHOD_OPTIONS);
	}

	{
		char str[] = "TRACE * HTTP/1.1\r\n\r\n";
		HTTP_Request req;
		int ret = http_parse_request(str, sizeof(str)-1, &req);
		TEST(ret == 20);
		TEST(req.method == HTTP_METHOD_TRACE);
	}

	{
		char str[] = "PATCH * HTTP/1.1\r\n\r\n";
		HTTP_Request req;
		int ret = http_parse_request(str, sizeof(str)-1, &req);
		TEST(ret == 20);
		TEST(req.method == HTTP_METHOD_PATCH);
	}
}

static void test_branch_coverage_parse_response(void)
{
	struct {
		int line;
		int ret;
		char *str;
	} error_ress[] = {
		{ __LINE__, -1, "@\r\n\r\n" },
		{ __LINE__, -1, "H\r\n\r\n" },
		{ __LINE__, -1, "H@\r\n\r\n" },
		{ __LINE__, -1, "HT\r\n\r\n" },
		{ __LINE__, -1, "HT@\r\n\r\n" },
		{ __LINE__, -1, "HTT\r\n\r\n" },
		{ __LINE__, -1, "HTT@\r\n\r\n" },
		{ __LINE__, -1, "HTTP\r\n\r\n" },
		{ __LINE__, -1, "HTTP@\r\n\r\n" },
		{ __LINE__, -1, "HTTP/\r\n\r\n" },
		{ __LINE__, -1, "HTTP/@\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1@\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.@\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1@\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 \r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 @\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 4\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 4@\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 40\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 40@\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 404\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 404@\r\n\r\n" },
		{ __LINE__, 17, "HTTP/1.1 404 \r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 404 \x1B\r\n\r\n" },
		{ __LINE__, 26, "HTTP/1.1 404 Not Found\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 404 Not Found\x1B\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 404 Not Found\x1B\nname:\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 404 Not Found\r\x1Bname:\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 404 Not Found\r\n@\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 404 Not Found\r\nn@\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 404 Not Found\r\nname\r\n\r\n" },
		{ __LINE__, 33, "HTTP/1.1 404 Not Found\r\nname:\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 404 Not Found\r\nname:\x1B\r\n\r\n" },
		{ __LINE__, 38, "HTTP/1.1 404 Not Found\r\nname:value\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 404 Not Found\r\nname  :value\r\n\r\n" },
		{ __LINE__, -1, "HTTP/1.1 404 Not Found\r\nname:val\rue\r\n\r\n" },

		{ __LINE__,  0, NULL },
	};

	for (int i = 0; error_ress[i].str; i++) {
		HTTP_Response res;
		int ret = http_parse_response(error_ress[i].str, strlen(error_ress[i].str), &res);
		if (ret != error_ress[i].ret) {
			fprintf(stderr, "Failed test at %s:%d (ret=%d, expected=%d)\n", __FILE__, error_ress[i].line, ret, error_ress[i].ret);
		}
	}
}

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

typedef struct {
	char *buf;
	int   cap;
	int   num;
} Buffer;

static void appendc(Buffer *b, char c)
{
	if (b->num < b->cap)
		b->buf[b->num] = c;
	b->num++;
}

static void appends(Buffer *b, HTTP_String s)
{
	if (b->num < b->cap) {
		int cpy = s.len;
		if (cpy > b->cap - b->num)
			cpy = b->cap - b->num;
		for (int i = 0; i < cpy; i++)
			b->buf[b->num + i] = s.ptr[i];
	}
	b->num += s.len;
}

static void appendi(Buffer *buf, unsigned int num)
{
	char tmp[10];

	tmp[0] = num / 1000000000; num %= 1000000000;
	tmp[1] = num / 100000000;  num %= 100000000;
	tmp[2] = num / 10000000;   num %= 10000000;
	tmp[3] = num / 1000000;    num %= 1000000;
	tmp[4] = num / 100000;     num %= 100000;
	tmp[5] = num / 10000;      num %= 10000;
	tmp[6] = num / 1000;       num %= 1000;
	tmp[7] = num / 100;        num %= 100;
	tmp[8] = num / 10;         num %= 10;
	tmp[9] = num;

	int leading_zeros = 0;
	while (leading_zeros < 9 && tmp[leading_zeros] == 0)
		leading_zeros++;

	for (int i = leading_zeros; i < 10; i++)
		tmp[i] += '0';

	appends(buf, (HTTP_String) {
		tmp + leading_zeros,
		10  - leading_zeros
	});
}

static int build_url(
	HTTP_String   scheme,
	HTTP_String   userinfo,
	HTTP_String   host,
	HTTP_HostMode mode,
	int           port,
	HTTP_String   path,
	HTTP_String   query,
	HTTP_String   fragment,
	char*         dst,
	int           cap)
{
	Buffer buf = {dst, cap, 0};
	appends(&buf, scheme);
	appendc(&buf, ':');
	if (mode != HTTP_HOST_MODE_VOID) {
		appendc(&buf, '/');
		appendc(&buf, '/');
		if (userinfo.len) {
			appends(&buf, userinfo);
			appendc(&buf, '@');
		}
		if (mode == HTTP_HOST_MODE_IPV6)
			appendc(&buf, '[');
		appends(&buf, host);
		if (mode == HTTP_HOST_MODE_IPV6)
			appendc(&buf, ']');
		if (port == -2)
			appendc(&buf, ':');
		else if (port != -1) {
			appendc(&buf, ':');
			appendi(&buf, port);
		}
	}
	appends(&buf, path);
	appends(&buf, query);
	appends(&buf, fragment);
	return buf.num;
}

static void test_url(HTTP_String scheme, HTTP_String userinfo,
	HTTP_String host, HTTP_HostMode mode, int port,
	HTTP_String path, HTTP_String query, HTTP_String fragment)
{
	char mem[1<<12];
	int num = build_url(scheme, userinfo, host, mode, port, path, query, fragment, mem, sizeof(mem));
	TEST(num < sizeof(mem));

	printf("Testing %.*s\n", num, mem);

	HTTP_URL url;
	int ret = http_parse_url(mem, num, &url);

	TEST_EQ(ret, num);
	TEST_EQ(url.scheme,   scheme);
	TEST_EQ(url.authority.userinfo, userinfo);
	if (port < 0)
		TEST_EQ(url.authority.port, 0);
	else
		TEST_EQ(url.authority.port, port);
	TEST_EQ((int) url.authority.host.mode, (int) mode);
	if (mode == HTTP_HOST_MODE_IPV4) {
		char tmp[1<<12];
		TEST(sizeof(tmp) > host.len);
		memcpy(tmp, host.ptr, host.len);
		tmp[host.len] = '\0';
		HTTP_IPv4 buf;
		TEST_EQ(inet_pton(AF_INET, tmp, &buf), 1);
		TEST_EQ((int) buf.data, (int) url.authority.host.ipv4.data);
	} else if (mode == HTTP_HOST_MODE_IPV6) {
		char tmp[1<<12];
		TEST(sizeof(tmp) > host.len);
		memcpy(tmp, host.ptr, host.len);
		tmp[host.len] = '\0';
		HTTP_IPv6 buf;
		TEST_EQ(inet_pton(AF_INET6, tmp, &buf), 1);
		TEST(!memcmp(&buf, &url.authority.host.ipv6, sizeof(HTTP_IPv6)));
	} else if (mode == HTTP_HOST_MODE_NAME) {
		TEST_EQ(host, url.authority.host.name);
	}
	TEST_EQ(url.path,     path);
	TEST_EQ(url.query,    query);
	TEST_EQ(url.fragment, fragment);
}

static void test_branch_coverage_parse_url(void)
{
	HTTP_String scheme_values[] = { S("http") };

	HTTP_String userinfo_values[] = { S(""), S("xxx:yyy") };
	
	struct host_values {
		HTTP_HostMode mode;
		HTTP_String   text;
	} host_values[] = {
		{ HTTP_HOST_MODE_VOID, S("")            },
		{ HTTP_HOST_MODE_IPV4, S("1.2.3.4")     },
		{ HTTP_HOST_MODE_IPV6, S("::")          },
		{ HTTP_HOST_MODE_IPV6, S("::1")         },
		{ HTTP_HOST_MODE_IPV6, S("1:2:3:4:A:B:C:D") },
		{ HTTP_HOST_MODE_NAME, S("example.com") },
		{ HTTP_HOST_MODE_NAME, S("1.2.3.256")   },
	};

	int port_values[] = { -1, 1, 8080 };

	HTTP_String path_values[] = { S(""), S("/"), S("/some/path.html") };

	HTTP_String query_values[] = { S(""), S("?"), S("?param1=hello&param2=sup") };

	HTTP_String fragment_values[] = { S(""), S("#"), S("#section0") };

	for (int i = 0; i < COUNT(scheme_values); i++)
		for (int j = 0; j < COUNT(userinfo_values); j++)
			for (int k = 0; k < COUNT(host_values); k++)
				for (int g = 0; g < COUNT(port_values); g++)
					for (int t = 0; t < COUNT(path_values); t++)
						for (int p = 0; p < COUNT(query_values); p++)
							for (int q = 0; q < COUNT(fragment_values); q++) {

								// Don't test URLs where the host isn't specified but the port or userinfo is
								if (host_values[k].mode == HTTP_HOST_MODE_VOID && (port_values[g] > -1 || userinfo_values[j].len))
									continue;

								// If the authority is missing, the path must not be empty
								if (host_values[k].mode == HTTP_HOST_MODE_VOID && path_values[t].len == 0)
									continue;

								test_url(
									scheme_values[i],
									userinfo_values[j],
									host_values[k].text,
									host_values[k].mode,
									port_values[g],
									path_values[t],
									query_values[p],
									fragment_values[q]
								);
							}
}

void test_branch_coverage_parse(void)
{
	test_branch_coverage_parse_request();
	test_branch_coverage_parse_response();
	test_branch_coverage_parse_url();
}
