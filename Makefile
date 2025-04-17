
all:
	gcc example.c tinyhttp.c -o blog -Wall -Wextra -ggdb -lws2_32