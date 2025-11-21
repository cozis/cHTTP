
#include <stdint.h>
#include <assert.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#endif
