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

#ifndef USE_SSL
#define USE_SSL (1)
#endif

#if USE_SSL != 0
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define UNUSED(X) ((void)(X))

typedef struct {
	void *ctx;
	void *ssl;
	int fd;
	unsigned use_ssl :1;
} socket_t;

static void *allocate(httpc_options_t *a, size_t sz) {
	assert(a);
	void *r = a->allocator(a->arena, NULL, 0, sz);
	return r ? memset(r, 0, sz) : r;
}

static void deallocate(httpc_options_t *a, void *ptr) {
	assert(a);
	a->allocator(a->arena, ptr, 0, 0);
}

static int socket_close(socket_t *s, httpc_options_t *a) {
	assert(s);
	if (!s)
		return HTTPC_OK;
	int r = HTTPC_OK;
#if USE_SSL != 0
	if (s->use_ssl) {
		if (s->ssl)
			SSL_free(s->ssl);
		s->ssl = NULL;
		if (s->ctx)
			SSL_CTX_free(s->ctx);
		s->ctx = NULL;
	}
#endif
	if (s->fd >= 0)
		r = closesocket(s->fd);
	s->fd = -1;
	deallocate(a, s);
	return r;
}

static int ssl_open(socket_t *s, httpc_options_t *a, const char *domain) {
	assert(s);
	assert(a);
	UNUSED(a);
	assert(domain);
	if (s->fd < 0)
		return HTTPC_ERROR;
#if USE_SSL == 0
	return HTTPC_ERROR;
#else
	const SSL_METHOD *method = TLS_client_method();
	s->ctx = SSL_CTX_new(method);
	if (!(s->ctx))
		goto fail;

	s->ssl = SSL_new(s->ctx);
	if (!(s->ssl))
		goto fail;

	SSL_set_fd(s->ssl, s->fd);

	if (SSL_set_tlsext_host_name(s->ssl, domain) != 1)
		goto fail;

	/* Better error logging could be done here... */
	if (SSL_connect(s->ssl) != 1)
		goto fail;
	return HTTPC_OK;
fail:
	return HTTPC_ERROR;
#endif
}

/* NB. read/write do not check if we can retry - too lazy atm to do so */
static int ssl_read(socket_t *s, unsigned char *buf, size_t *length) {
	assert(s);
	assert(buf);
	assert(length);
#if USE_SSL == 0
	return HTTPC_ERROR;
#else
	const size_t requested = *length;
	*length = 0;
	const int r = SSL_read(s->ssl, buf, requested);
	if (r < 0)
		return HTTPC_ERROR;
	*length = r;
	return HTTPC_OK;
#endif
}

static int ssl_write(socket_t *s, const unsigned char *buf, size_t *length) {
	assert(s);
	assert(buf);
	assert(length);
#if USE_SSL == 0
	return HTTPC_ERROR;
#else
	assert(*length < INT_MAX);
	if (*length == 0)
		return HTTPC_OK;
	const int r = SSL_write(s->ssl, buf, *length);
	*length = 0;
	if (r > 0)
		*length = r;
	return r > 0 ? HTTPC_OK : HTTPC_ERROR;
#endif
}

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
		init = -1;
		httpc_cleanup();
	}
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

int httpc_open(void **sock, httpc_options_t *a, void *opts, const char *host_or_ip, unsigned short port, int use_ssl) {
	assert(sock);
	assert(a);
	assert(host_or_ip);
	UNUSED(opts);
	UNUSED(a);
	struct addrinfo *servinfo = NULL, *p = NULL;
       	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};

	if (!USE_SSL && use_ssl)
		return HTTPC_ERROR;

	if (httpc_init() < 0)
		return HTTPC_ERROR;

	socket_t *s = allocate(a, sizeof *s);
	if (!s)
		return HTTPC_ERROR;
	s->use_ssl = use_ssl;
	s->fd = -1;

	port = port ? port : 80;

	char sport[32] = { 0 };
	snprintf(sport, sizeof sport, "%u", port);
	const int rv = getaddrinfo(host_or_ip, sport, &hints, &servinfo);
	if (rv != 0) {
		socket_close(s, a);
		return HTTPC_ERROR;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((s->fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			continue;
		}
		if (connect(s->fd, p->ai_addr, p->ai_addrlen) == -1) {
			closesocket(s->fd);
			continue;
		}
		break;
	}

	if (p == NULL) {
		freeaddrinfo(servinfo);
		socket_close(s, a);
		return HTTPC_ERROR;
	}

	char si[INET6_ADDRSTRLEN] = { 0 };
	if (NULL == inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), si, sizeof si)) {
		freeaddrinfo(servinfo);
		socket_close(s, a);
		return HTTPC_ERROR;
	}

	freeaddrinfo(servinfo);

	if (use_ssl) {
		if (ssl_open(s, a, host_or_ip) < 0) {
			socket_close(s, a);
			return HTTPC_ERROR;
		}
	}

	*sock = s;
	return HTTPC_OK;
}

int httpc_close(void *socket, httpc_options_t *a) {
	assert(a);
	UNUSED(a);
	return socket_close(socket, a);
}

int httpc_read(void *socket, unsigned char *buf, size_t *length) {
	assert(length);
	assert(buf);
	socket_t *s = socket;
	if (s->use_ssl)
		return ssl_read(s, buf, length);
	errno = 0;
	const intptr_t fd = s->fd;
	const ssize_t re = recv(fd, (char*)buf, *length, 0);
	if (re == -1) {
		*length = 0;
		return HTTPC_ERROR;
	}
	*length = re;
	return HTTPC_OK;
}

int httpc_write(void *socket, const unsigned char *buf, size_t *length) {
	assert(socket);
	assert(buf);
	assert(length);
	socket_t *s = socket;
	if (s->use_ssl)
		return ssl_write(s, buf, length);
	errno = 0;
	const intptr_t fd = s->fd;
	const ssize_t wr = send(fd, (const char *)buf, *length, 0);
	if ((size_t)wr != *length || wr == -1)
		return HTTPC_ERROR;
	*length = wr;
	return HTTPC_OK;
}

int httpc_sleep(unsigned long milliseconds) {
	Sleep(milliseconds);
	return HTTPC_OK;
}

int httpc_time(unsigned long *milliseconds) {
	assert(milliseconds);
	*milliseconds = GetTickCount();
	return HTTPC_OK;
}

