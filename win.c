#include "httpc.h"
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN8
#endif
#define WIN32_LEAN_AND_MEAN
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <winsock2.h>
#include <windows.h>
#include <Ws2tcpip.h>

#define UNUSED(X) ((void)(X))

static void httpc_cleanup(void) {
	(void)WSACleanup();
}

static int httpc_init(void) {
	static int init = 0; // !!
	if (init)
		return init;
	WSADATA d;
	const int r = WSAStartup(0x0202, &d) < 0 ? -1 : 1;
	init = r;
	if (atexit(httpc_cleanup) < 0) {
		//(void)httpc_log("atexit(httpc_cleanup) failed");
		init = -1;
		httpc_cleanup();
	}
	//(void)httpc_log("initialization %s", init < 0 ? "failed" : "passed");
	return init;
}

static void *get_in_addr(struct sockaddr *sa) {
	assert(sa);
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int httpc_logger(void *logger, const char *fmt, va_list ap) {
	assert(fmt);
	assert(logger);
	FILE *f = logger;
	va_list copy;
	va_copy(copy, ap);
	const int r = vfprintf(f, fmt, copy);
	va_end(copy);
	return r;
}

/* TODO: Add keepalive, timeout, ... */
int httpc_open(void **sock, void *opts, const char *host_or_ip, unsigned short port, int use_ssl) {
	assert(sock);
	assert(host_or_ip);
	UNUSED(opts);
	int sockfd = -1, rv = 0;
	struct addrinfo *servinfo = NULL, *p = NULL;
       	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};

	if (httpc_init() < 0) {
		//(void)httpc_log("Winsock initialization failed");
		return HTTPC_ERROR;
	}

	if (use_ssl) {
		//(void)httpc_log("SSL not implemented yet");
		return HTTPC_ERROR;
	}
	port = port ? port : 80;

	char sport[32] = { 0 };
	snprintf(sport, sizeof sport, "%u", port);
	if ((rv = getaddrinfo(host_or_ip, sport, &hints, &servinfo)) != 0) {
		//httpc_log("getaddrinfo: %s", gai_strerror(rv));
		return HTTPC_ERROR;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			//httpc_log("client: socket");
			continue;
		}
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			closesocket(sockfd);
			//httpc_log("client: connect");
			continue;
		}
		break;
	}

	if (p == NULL) {
		//httpc_log("client: failed to connect");
		freeaddrinfo(servinfo);
		return HTTPC_ERROR;
	}

	char s[INET6_ADDRSTRLEN] = { 0 };
	if (NULL == inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s)) {
		(void)closesocket(sockfd);
		freeaddrinfo(servinfo);
		//httpc_log("inet_ntop error");
		return HTTPC_ERROR;
	}
	//httpc_log("client: connecting to '%s'", s);

	freeaddrinfo(servinfo);
	*sock = (void*)(intptr_t)sockfd;
	return HTTPC_OK;
}

int httpc_close(void *socket) {
	return closesocket((intptr_t)socket) < 0 ? HTTPC_ERROR : HTTPC_OK;
}

int httpc_read(void *socket, unsigned char *buf, size_t *length) {
	assert(length);
	assert(buf);
	errno = 0;
	const intptr_t fd = (intptr_t)socket;
	const ssize_t re = recv(fd, (char*)buf, *length, 0);
	if (re == -1) {
		//(void)httpc_log("read error: %ld/%s/%d", (long)re, strerror(errno), (int)fd);
		*length = 0;
		return HTTPC_ERROR;
	}
	*length = re;
	return HTTPC_OK;
}

int httpc_write(void *socket, const unsigned char *buf, const size_t length) {
	assert(buf);
	errno = 0;
	const intptr_t fd = (intptr_t)socket;
	const ssize_t wr = send(fd, (const char *)buf, length, 0);
	if ((size_t)wr != length || wr == -1) {
		//(void)httpc_log("write error: %ld/%s/%d", (long)wr, strerror(errno), (int)fd);
		return HTTPC_ERROR;
	}
	return HTTPC_OK;
}

int httpc_sleep(unsigned long milliseconds) {
	Sleep(milliseconds);
	return HTTPC_OK;
}

