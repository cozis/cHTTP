#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include "test.h"

static void *memfunc(HTTP_MemoryFuncTag tag,
	void *ptr, int len, void *data)
{
	(void) data;
	switch (tag) {

		case HTTP_MEMFUNC_MALLOC:
		{
			void *ptr = NULL;

			int x = rand() & 31;
			if (x == 0)
				ptr = malloc(len);
			return ptr;
		}

		case HTTP_MEMFUNC_FREE:
		free(ptr);
		return NULL;
	}
	return NULL;
}

const char *http_statestr(int state)
{
	switch (state) {
		case HTTP_ENGINE_STATE_NONE                : return "NONE";
		case HTTP_ENGINE_STATE_CLIENT_PREP_URL     : return "CLIENT_PREP_URL";
		case HTTP_ENGINE_STATE_CLIENT_PREP_HEADER  : return "CLIENT_PREP_HEADER";
		case HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF: return "CLIENT_PREP_BODY_BUF";
		case HTTP_ENGINE_STATE_CLIENT_PREP_BODY_ACK: return "CLIENT_PREP_BODY_ACK";
		case HTTP_ENGINE_STATE_CLIENT_PREP_ERROR   : return "CLIENT_PREP_ERROR";
		case HTTP_ENGINE_STATE_CLIENT_SEND_BUF     : return "CLIENT_SEND_BUF";
		case HTTP_ENGINE_STATE_CLIENT_SEND_ACK     : return "CLIENT_SEND_ACK";
		case HTTP_ENGINE_STATE_CLIENT_RECV_BUF     : return "CLIENT_RECV_BUF";
		case HTTP_ENGINE_STATE_CLIENT_RECV_ACK     : return "CLIENT_RECV_ACK";
		case HTTP_ENGINE_STATE_CLIENT_READY        : return "CLIENT_READY";
		case HTTP_ENGINE_STATE_CLIENT_CLOSED       : return "CLIENT_CLOSED";
		case HTTP_ENGINE_STATE_SERVER_RECV_BUF     : return "SERVER_RECV_BUF";
		case HTTP_ENGINE_STATE_SERVER_RECV_ACK     : return "SERVER_RECV_ACK";
		case HTTP_ENGINE_STATE_SERVER_PREP_STATUS  : return "SERVER_PREP_STATUS";
		case HTTP_ENGINE_STATE_SERVER_PREP_HEADER  : return "SERVER_PREP_HEADER";
		case HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF: return "SERVER_PREP_BODY_BUF";
		case HTTP_ENGINE_STATE_SERVER_PREP_BODY_ACK: return "SERVER_PREP_BODY_ACK";
		case HTTP_ENGINE_STATE_SERVER_PREP_ERROR   : return "SERVER_PREP_ERROR";
		case HTTP_ENGINE_STATE_SERVER_SEND_BUF     : return "SERVER_SEND_BUF";
		case HTTP_ENGINE_STATE_SERVER_SEND_ACK     : return "SERVER_SEND_ACK";
		case HTTP_ENGINE_STATE_SERVER_CLOSED       : return "SERVER_CLOSED";
	}
	return "???";
}

static sig_atomic_t stop = 0;

static void handle_signal(int dummy)
{
	stop = 1;
}

void test_fuzz_engine(void)
{
	signal(SIGINT, handle_signal);

	char txt1[] = "";
	char txt2[] = "GET / HTTP/1.1\r\n\r\n";
	char txt3[] = "GET / HTTP/1.1\n";
	char txt4[] = "HTTP/1.1 200 OK\r\n";
	char txt5[] = "HTTP/1.1 200 OK\r\n\r\n";

	int next_recvack = 0;
	int next_sendack = 0;
	int next_bodyack = 0;
	int curr_bodycap = 0;
	int client = 0;
	HTTP_Engine eng;
	http_engine_init(&eng, client, memfunc, NULL);
	while (!stop) {
		//printf("%s\n", http_statestr(http_engine_state(&eng)));
		switch (rand() % 21) {

			int max;
			char *buf;

			case 0:
			//printf("http_engine_free/http_engine_init\n");
			client = !client;
			http_engine_free(&eng);
			http_engine_init(&eng, client, memfunc, NULL);
			next_recvack = 0;
			next_sendack = 0;
			next_bodyack = 0;
			curr_bodycap = 0;
			break;

			case 1:
			//printf("http_engine_recvbuf (1)\n");
			buf = http_engine_recvbuf(&eng, &max);
			memcpy(buf, txt1, strlen(txt1));
			next_recvack = strlen(txt1);
			break;

			case 2:
			//printf("http_engine_recvbuf (2)\n");
			buf = http_engine_recvbuf(&eng, &max);
			if (buf) {
				memcpy(buf, txt2, strlen(txt2));
				next_recvack = strlen(txt2);
			}
			break;

			case 3:
			//printf("http_engine_recvbuf (3)\n");
			buf = http_engine_recvbuf(&eng, &max);
			if (buf) {
				memcpy(buf, txt3, strlen(txt3));
				next_recvack = strlen(txt3);
			}
			break;

			case 4:
			//printf("http_engine_recvbuf (4)\n");
			buf = http_engine_recvbuf(&eng, &max);
			if (buf) {
				memcpy(buf, txt4, strlen(txt4));
				next_recvack = strlen(txt4);
			}
			break;

			case 5:
			//printf("http_engine_recvbuf (5)\n");
			buf = http_engine_recvbuf(&eng, &max);
			if (buf) {
				memcpy(buf, txt5, strlen(txt5));
				next_recvack = strlen(txt5);
			}
			break;

			case 6:
			//printf("http_engine_recvack\n");
			http_engine_recvack(&eng, next_recvack);
			next_recvack = 0;
			break;

			case 7:
			//printf("http_engine_sendbuf\n");
			buf = http_engine_sendbuf(&eng, &max);
			if (max)
				next_sendack = rand() % max;
			break;

			case 8:
			//printf("http_engine_sendack\n");
			http_engine_sendack(&eng, next_sendack);
			next_sendack = 0;
			break;

			case 9:
			//printf("http_engine_getreq\n");
			http_engine_getreq(&eng);
			break;

			case 10:
			//printf("http_engine_getres\n");
			http_engine_getres(&eng);
			break;

			case 11:
			//printf("http_engine_url\n");
			http_engine_url(&eng, HTTP_METHOD_GET, "", 0);
			break;

			case 12:
			//printf("http_engine_url\n");
			http_engine_url(&eng, HTTP_METHOD_GET, "http://127.0.0.1/hello", 0);
			break;

			case 13:
			//printf("http_engine_status\n");
			http_engine_status(&eng, 200);
			break;

			case 14:
			//printf("http_engine_header\n");
			http_engine_header(&eng, "x:y", -1);
			break;

			case 15:
			//printf("http_engine_bodycap\n");
			http_engine_bodycap(&eng, rand() % 1000);
			break;

			case 16:
			//printf("http_engine_bodybuf\n");
			buf = http_engine_bodybuf(&eng, &max);
			if (buf && max) {
				max = rand() % max;
				memset(buf, 0xFF, max);
				next_bodyack = max;
			}
			break;

			case 17:
			//printf("http_engine_bodyack\n");
			http_engine_bodyack(&eng, next_bodyack);
			next_bodyack = 0;
			break;

			case 18:
			//printf("http_engine_done\n");
			http_engine_done(&eng);
			break;

			case 19:
			//printf("http_engine_undo\n");
			http_engine_undo(&eng);
			break;

			case 20:
			//printf("http_engine_close\n");
			http_engine_close(&eng);
			break;
		}
	}
	http_engine_free(&eng);
}