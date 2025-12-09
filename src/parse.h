
#define CHTTP_MAX_HEADERS 32

typedef struct {
	unsigned int data;
} CHTTP_IPv4;

typedef struct {
	unsigned short data[8];
} CHTTP_IPv6;

typedef enum {
	CHTTP_HOST_MODE_VOID = 0,
	CHTTP_HOST_MODE_NAME,
	CHTTP_HOST_MODE_IPV4,
	CHTTP_HOST_MODE_IPV6,
} CHTTP_HostMode;

typedef struct {
	CHTTP_HostMode mode;
	CHTTP_String   text;
	union {
		CHTTP_String name;
		CHTTP_IPv4   ipv4;
		CHTTP_IPv6   ipv6;
	};
} CHTTP_Host;

typedef struct {
	CHTTP_String userinfo;
	CHTTP_Host   host;
	int         port;
} CHTTP_Authority;

// ZII
typedef struct {
	CHTTP_String    scheme;
	CHTTP_Authority authority;
	CHTTP_String    path;
	CHTTP_String    query;
	CHTTP_String    fragment;
} CHTTP_URL;

typedef enum {
	CHTTP_METHOD_GET,
	CHTTP_METHOD_HEAD,
	CHTTP_METHOD_POST,
	CHTTP_METHOD_PUT,
	CHTTP_METHOD_DELETE,
	CHTTP_METHOD_CONNECT,
	CHTTP_METHOD_OPTIONS,
	CHTTP_METHOD_TRACE,
	CHTTP_METHOD_PATCH,
} CHTTP_Method;

typedef struct {
	CHTTP_String name;
	CHTTP_String value;
} CHTTP_Header;

typedef struct {
    bool        secure;
	CHTTP_Method method;
	CHTTP_URL    url;
	int         minor;
	int         num_headers;
	CHTTP_Header headers[CHTTP_MAX_HEADERS];
	CHTTP_String body;
} CHTTP_Request;

typedef struct {
    void*       context;
	int         minor;
	int         status;
	CHTTP_String reason;
	int         num_headers;
	CHTTP_Header headers[CHTTP_MAX_HEADERS];
	CHTTP_String body;
} CHTTP_Response;

int         chttp_parse_ipv4     (char *src, int len, CHTTP_IPv4     *ipv4);
int         chttp_parse_ipv6     (char *src, int len, CHTTP_IPv6     *ipv6);
int         chttp_parse_url      (char *src, int len, CHTTP_URL      *url);
int         chttp_parse_request  (char *src, int len, CHTTP_Request  *req);
int         chttp_parse_response (char *src, int len, CHTTP_Response *res);

int         chttp_find_header    (CHTTP_Header *headers, int num_headers, CHTTP_String name);

CHTTP_String chttp_get_cookie     (CHTTP_Request *req, CHTTP_String name);
CHTTP_String chttp_get_param      (CHTTP_String body, CHTTP_String str, char *mem, int cap);
int         chttp_get_param_i    (CHTTP_String body, CHTTP_String str);

// Checks whether the request was meant for the host with the given
// domain an port. If port is -1, the default value of 80 is assumed.
bool chttp_match_host(CHTTP_Request *req, CHTTP_String domain, int port);

// Date and cookie types for Set-Cookie header parsing
typedef enum {
    CHTTP_WEEKDAY_MON,
    CHTTP_WEEKDAY_TUE,
    CHTTP_WEEKDAY_WED,
    CHTTP_WEEKDAY_THU,
    CHTTP_WEEKDAY_FRI,
    CHTTP_WEEKDAY_SAT,
    CHTTP_WEEKDAY_SUN,
} CHTTP_WeekDay;

typedef enum {
    CHTTP_MONTH_JAN,
    CHTTP_MONTH_FEB,
    CHTTP_MONTH_MAR,
    CHTTP_MONTH_APR,
    CHTTP_MONTH_MAY,
    CHTTP_MONTH_JUN,
    CHTTP_MONTH_JUL,
    CHTTP_MONTH_AUG,
    CHTTP_MONTH_SEP,
    CHTTP_MONTH_OCT,
    CHTTP_MONTH_NOV,
    CHTTP_MONTH_DEC,
} CHTTP_Month;

typedef struct {
    CHTTP_WeekDay week_day;
    int          day;
    CHTTP_Month   month;
    int          year;
    int          hour;
    int          minute;
    int          second;
} CHTTP_Date;

typedef struct {
    CHTTP_String name;
    CHTTP_String value;

    bool secure;
    bool chttp_only;

    bool have_date;
    CHTTP_Date date;

    bool have_max_age;
    uint32_t max_age;

    bool have_domain;
    CHTTP_String domain;

    bool have_path;
    CHTTP_String path;
} CHTTP_SetCookie;

// Parses a Set-Cookie header value
// Returns 0 on success, -1 on error
int chttp_parse_set_cookie(CHTTP_String str, CHTTP_SetCookie *out);
