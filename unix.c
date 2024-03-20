/* The Unix callbacks.
 *
 * I hate TLS/SSL, it is far to complex, the interfaces suck, and
 * it is a pain to use in an embedded system (it requires a million
 * different algorithms (is the ChaBlowCurveAES-256 algorithm more secure 
 * than FishARC4ElipticRSA-128? No one cares you weeny, just pick one) 
 * if you want to be compatible with any system and requires a ludicrous 
 * amount of memory per connection (~16-32KiB)), has too many optional 
 * options and options which are optional, and several different encoding 
 * and file formats for the certificates (just pick one!).
 *
 * I hope something simpler replaces it. I swear that the makers of
 * cryptographic software deliberately make it difficult to use and
 * integrate so as to weaken the security of everything, a conspiracy
 * by the C.I.A would make perfect sense as to why it is so shit, hell,
 * at least that would make sense!
 *
 * Luckily I do not have to care that much about it and can just
 * wrap everything up and link to a giant blob of fail, cordoning
 * everything off in here. 
 *
 * Mind you the socket interface in Unix kind of sucks as well. At
 * least that has the excuse of not being made by the original makers
 * of Unix. */
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
#include <time.h>
/*#include <netinet/tcp.h> // Not portable, needed for keepalive */

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
		r = close(s->fd);
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

/* see https://beej.us/guide/bgnet/html/#cb46-22 */
static void *get_in_addr(struct sockaddr *sa) {
	assert(sa);
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int httpc_logger(httpc_options_t *a, void *logger, const char *fmt, va_list ap) {
	assert(a);
	assert(fmt);
	assert(logger);
	FILE *f = logger;
	va_list copy;
	va_copy(copy, ap);
	const int r = vfprintf(f, fmt, copy);
	va_end(copy);
	return r;
}

int httpc_open(httpc_options_t *a, void **sock, void *opts, const char *host_or_ip, unsigned short port, int use_ssl) {
	assert(sock);
	assert(a);
	assert(host_or_ip);
	UNUSED(opts);
	struct addrinfo *servinfo = NULL, *p = NULL;
       	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};

	if (!USE_SSL && use_ssl)
		return HTTPC_ERROR;

	socket_t *s = allocate(a, sizeof *s);
	if (!s)
		return HTTPC_ERROR;
	s->use_ssl = use_ssl;
	s->fd = -1;

	port = port ? port : 80;

	char sport[32] = { 0 };
	snprintf(sport, sizeof sport, "%u", port);
	if (getaddrinfo(host_or_ip, sport, &hints, &servinfo) != 0)
		goto fail;

	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((s->fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			continue;
		}
		if (connect(s->fd, p->ai_addr, p->ai_addrlen) == -1) {
			close(s->fd);
			s->fd = -1;
			continue;
		}
		break;
	}

	if (p == NULL) {
		freeaddrinfo(servinfo);
		servinfo = NULL;
		goto fail;
	}

	char ip[INET6_ADDRSTRLEN] = { 0 };
	if (NULL == inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), ip, sizeof ip))
		goto fail;

	freeaddrinfo(servinfo);
	servinfo = NULL;

	/* If you want to set the keep alive as well:
	setsockopt(s->fd, IPPROTO_TCP, TCP_KEEPCNT,   &(int){   5 }, sizeof(int));
	setsockopt(s->fd, IPPROTO_TCP, TCP_KEEPIDLE,  &(int){  30 }, sizeof(int));
	setsockopt(s->fd, IPPROTO_TCP, TCP_KEEPINTVL, &(int){ 120 }, sizeof(int));
	*/

	struct timeval tx_tv = { .tv_sec = 30 }, rx_tv = { .tv_sec = 30 };

	if (setsockopt(s->fd, SOL_SOCKET, SO_SNDTIMEO, &tx_tv, sizeof tx_tv) < 0)
		goto fail;

	if (setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, &rx_tv, sizeof rx_tv) < 0)
		goto fail;

	if (use_ssl) {
		if (ssl_open(s, a, host_or_ip) < 0)
			goto fail;
	}
	*sock = s;
	return HTTPC_OK;
fail:
	*sock = NULL;
	socket_close(s, a);
	if (servinfo) {
		freeaddrinfo(servinfo);
		servinfo = NULL;
	}
	return HTTPC_ERROR;
}

int httpc_close(httpc_options_t *a, void *socket) {
	assert(a);
	return socket_close(socket, a);
}

int httpc_read(httpc_options_t *a, void *socket, unsigned char *buf, size_t *length) {
	assert(a);
	assert(socket);
	assert(length);
	assert(buf);
	socket_t *s = socket;
	if (s->use_ssl)
		return ssl_read(s, buf, length);
	const int fd = s->fd;
	ssize_t re = 0;
again:
	errno = 0;
	re = read(fd, buf, *length);
	if (re == -1) {
		if (errno == EINTR)
			goto again;
		*length = 0;
		return HTTPC_ERROR;
	}
	*length = re;
	return HTTPC_OK;
}

int httpc_write(httpc_options_t *a, void *socket, const unsigned char *buf, size_t *length) {
	assert(a);
	assert(socket);
	assert(buf);
	assert(length);
	socket_t *s = socket;
	if (s->use_ssl)
		return ssl_write(s, buf, length);
	const int fd = s->fd;
	ssize_t wr = 0;
again:
	errno = 0;
	wr = write(fd, buf, *length);
	if ((size_t)wr != *length || wr == -1) {
		if (errno == EINTR)
			goto again;
		return HTTPC_ERROR;
	}
	*length = wr;
	return HTTPC_OK;
}

int httpc_sleep(httpc_options_t *a, unsigned long milliseconds) {
	assert(a);
	return usleep(milliseconds * 1000ul) < 0 ? HTTPC_ERROR : HTTPC_OK;
}

int httpc_time(httpc_options_t *a, unsigned long *milliseconds) {
	assert(a);
	assert(milliseconds);
	*milliseconds = 0;
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &t) < 0)
		return HTTPC_ERROR;
    	*milliseconds = (t.tv_sec * 1000ul) + (t.tv_nsec / (1000000ul));
	return HTTPC_OK;
}

