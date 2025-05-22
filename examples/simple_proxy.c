#include <stdio.h>
#include "../tinyhttp.h"

int main(void)
{
	HTTP_Proxy proxy;
	int ret = http_proxy_init(&proxy, "127.0.0.1", 8080);
	if (ret < 0) {
		printf("http_proxy_init failed\n");
		return -1;
	}

	for (;;)
		http_proxy_wait(&proxy, -1);

	http_proxy_free(&proxy);
	return 0;
}
