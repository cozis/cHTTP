
#define HTTP_MAX_HEADERS 32

typedef struct {
	unsigned int data;
} HTTP_IPv4;

typedef struct {
	unsigned short data[8];
} HTTP_IPv6;

typedef enum {
	HTTP_HOST_MODE_VOID = 0,
	HTTP_HOST_MODE_NAME,
	HTTP_HOST_MODE_IPV4,
	HTTP_HOST_MODE_IPV6,
} HTTP_HostMode;

typedef struct {
	HTTP_HostMode mode;
	HTTP_String   text;
	union {
		HTTP_String name;
		HTTP_IPv4   ipv4;
		HTTP_IPv6   ipv6;
	};
} HTTP_Host;

typedef struct {
	HTTP_String userinfo;
	HTTP_Host   host;
	int         port;
} HTTP_Authority;

// ZII
typedef struct {
	HTTP_String    scheme;
	HTTP_Authority authority;
	HTTP_String    path;
	HTTP_String    query;
	HTTP_String    fragment;
} HTTP_URL;

typedef enum {
	HTTP_METHOD_GET,
	HTTP_METHOD_HEAD,
	HTTP_METHOD_POST,
	HTTP_METHOD_PUT,
	HTTP_METHOD_DELETE,
	HTTP_METHOD_CONNECT,
	HTTP_METHOD_OPTIONS,
	HTTP_METHOD_TRACE,
	HTTP_METHOD_PATCH,
} HTTP_Method;

typedef struct {
	HTTP_String name;
	HTTP_String value;
} HTTP_Header;

typedef struct {
    bool        secure;
	HTTP_Method method;
	HTTP_URL    url;
	int         minor;
	int         num_headers;
	HTTP_Header headers[HTTP_MAX_HEADERS];
	HTTP_String body;
} HTTP_Request;

typedef struct {
    void*       context;
	int         minor;
	int         status;
	HTTP_String reason;
	int         num_headers;
	HTTP_Header headers[HTTP_MAX_HEADERS];
	HTTP_String body;
} HTTP_Response;

int         http_parse_ipv4     (char *src, int len, HTTP_IPv4     *ipv4);
int         http_parse_ipv6     (char *src, int len, HTTP_IPv6     *ipv6);
int         http_parse_url      (char *src, int len, HTTP_URL      *url);
int         http_parse_request  (char *src, int len, HTTP_Request  *req);
int         http_parse_response (char *src, int len, HTTP_Response *res);

int         http_find_header    (HTTP_Header *headers, int num_headers, HTTP_String name);

HTTP_String http_get_cookie     (HTTP_Request *req, HTTP_String name);
HTTP_String http_get_param      (HTTP_String body, HTTP_String str, char *mem, int cap);
int         http_get_param_i    (HTTP_String body, HTTP_String str);

// Checks whether the request was meant for the host with the given
// domain an port. If port is -1, the default value of 80 is assumed.
bool http_match_host(HTTP_Request *req, HTTP_String domain, int port);

// Date and cookie types for Set-Cookie header parsing
typedef enum {
    HTTP_WEEKDAY_MON,
    HTTP_WEEKDAY_TUE,
    HTTP_WEEKDAY_WED,
    HTTP_WEEKDAY_THU,
    HTTP_WEEKDAY_FRI,
    HTTP_WEEKDAY_SAT,
    HTTP_WEEKDAY_SUN,
} HTTP_WeekDay;

typedef enum {
    HTTP_MONTH_JAN,
    HTTP_MONTH_FEB,
    HTTP_MONTH_MAR,
    HTTP_MONTH_APR,
    HTTP_MONTH_MAY,
    HTTP_MONTH_JUN,
    HTTP_MONTH_JUL,
    HTTP_MONTH_AUG,
    HTTP_MONTH_SEP,
    HTTP_MONTH_OCT,
    HTTP_MONTH_NOV,
    HTTP_MONTH_DEC,
} HTTP_Month;

typedef struct {
    HTTP_WeekDay week_day;
    int          day;
    HTTP_Month   month;
    int          year;
    int          hour;
    int          minute;
    int          second;
} HTTP_Date;

typedef struct {
    HTTP_String name;
    HTTP_String value;

    bool secure;
    bool http_only;

    bool have_date;
    HTTP_Date date;

    bool have_max_age;
    uint32_t max_age;

    bool have_domain;
    HTTP_String domain;

    bool have_path;
    HTTP_String path;
} HTTP_SetCookie;

// Parses a Set-Cookie header value
// Returns 0 on success, -1 on error
int http_parse_set_cookie(HTTP_String str, HTTP_SetCookie *out);
