#include "httpc.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
/*#include <netinet/tcp.h> // Not portable, needed for keepalive */

#define UNUSED(X) ((void)(X))

/* see https://beej.us/guide/bgnet/html/#cb46-22 */

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
			//httpc_log("client socket: %s", strerror(errno));
			continue;
		}
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			sockfd = -1;
			//httpc_log("client connect: %s", strerror(errno));
			continue;
		}
		break;
	}

	if (p == NULL) {
		//httpc_log("client failed to connect");
		freeaddrinfo(servinfo);
		return HTTPC_ERROR;
	}

	char s[INET6_ADDRSTRLEN] = { 0 };
	if (NULL == inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s)) {
		//httpc_log("inet_ntop error");
		goto fail;
	}

	freeaddrinfo(servinfo);
	servinfo = NULL;

	/* If you want to set the keep alive as well:
	setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT,   &(int){   5 }, sizeof(int));
	setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE,  &(int){  30 }, sizeof(int));
	setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &(int){ 120 }, sizeof(int));
	*/

	struct timeval tx_tv = { .tv_sec = 30 }, rx_tv = { .tv_sec = 30 };

	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tx_tv, sizeof tx_tv) < 0) {
		//httpc_log("SO_SNDTIMEO failed");
		goto fail;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &rx_tv, sizeof rx_tv) < 0) {
		//httpc_log("SO_RCVTIMEO failed");
		goto fail;
	}

	*sock = (void*)(intptr_t)sockfd;
	//httpc_log("client: connecting to '%s'", s);
	return HTTPC_OK;
fail:
	if (sockfd != -1)
		close(sockfd);
	if (servinfo) {
		freeaddrinfo(servinfo);
		servinfo = NULL;
	}
	return HTTPC_ERROR;
}

int httpc_close(void *socket) {
	return close((intptr_t)socket) < 0 ? HTTPC_ERROR : HTTPC_OK;
}

int httpc_read(void *socket, unsigned char *buf, size_t *length) {
	assert(length);
	assert(buf);
	const intptr_t fd = (intptr_t)socket;
	ssize_t re = 0;
again:
	errno = 0;
	re = read(fd, buf, *length);
	if (re == -1) {
		if (errno == EINTR)
			goto again;
		//(void)httpc_log("read error: %ld/%s/%d", (long)re, strerror(errno), (int)fd);
		*length = 0;
		return HTTPC_ERROR;
	}
	*length = re;
	return HTTPC_OK;
}

int httpc_write(void *socket, const unsigned char *buf, const size_t length) {
	assert(buf);
	const intptr_t fd = (intptr_t)socket;
	ssize_t wr = 0;
again:
	errno = 0;
	wr = write(fd, buf, length);
	if ((size_t)wr != length || wr == -1) {
		if (errno == EINTR)
			goto again;
		//(void)httpc_log("write error: %ld/%s/%d", (long)wr, strerror(errno), (int)fd);
		return HTTPC_ERROR;
	}
	return HTTPC_OK;
}

int httpc_sleep(unsigned long milliseconds) {
	return usleep(milliseconds * 1000ul) < 0 ? HTTPC_ERROR : HTTPC_OK;
}

