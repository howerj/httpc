/* Project:    Embeddable HTTP 1.0/1.1 Client
 * Author:     Richard James Howe
 * License:    The Unlicense
 * Email:      howe.r.j.89@gmail.com
 * Repository: https://github.com/howerj/httpc */

#include "httpc.h"
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <limits.h>

#ifndef HTTPC_STACK_BUFFER_SIZE /* buffers allocated on the stack, responsible for some arbitrary limits as well. */
#define HTTPC_STACK_BUFFER_SIZE (512ul)
#endif

#ifndef HTTPC_VERSION
#define HTTPC_VERSION (0x000000ul) /* all zeros = built incorrectly */
#endif

#ifndef HTTPC_TESTS_ON /* Build in tests to the program */
#define HTTPC_TESTS_ON (1u)
#endif

#ifndef HTTPC_LOGGING
#define HTTPC_LOGGING (1u)
#endif

#ifndef HTTPC_CONNECTION_ATTEMPTS
#define HTTPC_CONNECTION_ATTEMPTS (3u)
#endif

#ifndef HTTPC_REDIRECT_MAX
#define HTTPC_REDIRECT_MAX (3u)
#endif

#ifndef HTTPC_MAX_HEADER /* maximum size for the header; 0 == infinite length allowed */
#define HTTPC_MAX_HEADER (8192ul)
#endif

#define USED(X)                 ((void)(X)) /* warning suppression: variable is used conditionally */
#define UNUSED(X)               ((void)(X)) /* warning suppression: variable is unused in function */
#define MAX(X, Y)               ((X) > (Y) ? (X) : (Y))
#define MIN(X, Y)               ((X) < (Y) ? (X) : (Y))
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define implies(P, Q)           assert(!(P) || (Q))

typedef struct {
	unsigned char *buffer;
	size_t allocated, used;
} buffer_t;

typedef unsigned long length_t;

/* NB. It might be best to allocate any large buffers here instead of
 * on the stack so the user can control allocations a bit more. */
struct httpc {
	httpc_options_t os;
	httpc_callback fn;
	void *fn_param;
	int argc;    /* extra headers count */
	char **argv; /* extra headers, can be NULL if argc == 0 */
	/* These strings point into 'url', which has been modified from the
	 * original URL to contain a bunch of NUL terminated strings where the
	 * delimiters were */
	char *domain /* or IPv4/IPv6 */, *userpass, *path, *url;
	void *socket;
	length_t position, length, max;
	unsigned retries, redirects; /* retry count, redirect count */
	unsigned retries_max, redirects_max;
	unsigned response, v1, v2; /* HTTP response, HTTP version (1.0 or 1.1) */
	unsigned short port;
	unsigned use_ssl       :1, /* if set then SSL should be used on the connection */
		 fatal         :1, /* if set then something has gone fatally wrong */
		 accept_ranges :1, /* if set then the server accepts ranges */
		 identity      :1, /* 1 == identity encoded, 0 == chunked */
		 redirect      :1, /* if set then a redirect is going on */
		 length_set    :1; /* has length been set on a PUT/POST? */
};

/* Modified from: <https://stackoverflow.com/questions/342409>
 * - Output buffer is NUL terminated on a successful encoding
 * - Returned output length is equivalent to strlen(out)
 * - Returns negative on error, zero on success. */
static int base64_encode(const unsigned char *in, const size_t input_length, unsigned char *out, size_t *output_length) {
	assert(in);
	assert(out);
	/* assert(shake_it_all_about); */
	const size_t out_buffer_length = *output_length;
	const size_t encoded_length  = 4ull * ((input_length + 2ull) / 3ull);

	if (out_buffer_length < (encoded_length + 1/*NUL*/))
		return -1;

	for (size_t i = 0, j = 0; i < input_length;) {
		static const char encoding_table[] = {
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
			'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
			'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
			'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
		};
		const uint32_t octet_a = i < input_length ? (unsigned char)in[i++] : 0;
		const uint32_t octet_b = i < input_length ? (unsigned char)in[i++] : 0;
		const uint32_t octet_c = i < input_length ? (unsigned char)in[i++] : 0;
		const uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
		out[j++] = encoding_table[(triple >> (3 * 6)) & 0x3F];
		out[j++] = encoding_table[(triple >> (2 * 6)) & 0x3F];
		out[j++] = encoding_table[(triple >> (1 * 6)) & 0x3F];
		out[j++] = encoding_table[(triple >> (0 * 6)) & 0x3F];
	}

	static const int mod_table[] = { 0, 2, 1 };
	for (int i = 0; i < mod_table[input_length % 3]; i++)
		out[encoded_length - 1 - i] = '=';
	out[encoded_length] = '\0';
	*output_length = encoded_length;
	return 0;
}

static inline void reverse(char * const r, const size_t length) {
	assert(r);
	const size_t last = length - 1;
	for (size_t i = 0; i < length / 2ul; i++) {
		const size_t t = r[i];
		r[i] = r[last - i];
		r[last - i] = t;
	}
}

static unsigned num_to_str(char b[64 + 1], unsigned long u, const unsigned long base) {
	assert(b);
	assert(base >= 2 && base <= 36);
	unsigned i = 0;
	do {
		const unsigned long q = u % base;
		const unsigned long r = u / base;
		b[i++] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[q];
		u = r;
	} while (u);
	b[i] = '\0';
	reverse(b, i);
	return i;
}

int httpc_version(unsigned long *version) {
	assert(version);
	unsigned long spec = 0;
	spec |= HTTPC_TESTS_ON << 0;
	spec |= HTTPC_LOGGING  << 1;
	*version = (spec << 24) | HTTPC_VERSION;
	return HTTPC_VERSION == 0 ? HTTPC_ERROR : HTTPC_OK;
}

static int httpc_kill(httpc_t *h) {
	assert(h);
	h->fatal = 1;
	return HTTPC_ERROR;
}

static int httpc_dead(httpc_t *h) {
	assert(h);
	return h->fatal;
}

#ifdef __GNUC__
#define HTTPC_LOG_FMT_ATTR __attribute__ ((format (printf, 2, 3)))
#define HTTPC_LOG_LINE_ATTR __attribute__ ((format (printf, 6, 7)))
static void httpc_log_fmt(httpc_t *h, const char *fmt, ...) HTTPC_LOG_FMT_ATTR;
static int httpc_log_line(httpc_t *h, const char *type, int die, int ret, const unsigned line, const char *fmt, ...) HTTPC_LOG_LINE_ATTR;
#else
#define HTTPC_LOG_FMT_ATTR
#define HTTPC_LOG_LINE_ATTR
#endif

static void httpc_log_fmt(httpc_t *h, const char *fmt, ...) {
	assert(fmt);
	va_list ap;
	va_start(ap, fmt);
	const int r = h->os.logger(h->os.logfile, fmt, ap);
	va_end(ap);
	if (r < 0)
		(void)httpc_kill(h);
}

static int httpc_log_line(httpc_t *h, const char *type, int die, int ret, const unsigned line, const char *fmt, ...) {
	assert(h);
	assert(fmt);
	if (h->os.flags & HTTPC_OPT_LOGGING_ON) {
		va_list ap;
		httpc_log_fmt(h, "%s:%u ", type, line);
		va_start(ap, fmt);
		if (h->os.logger(h->os.logfile, fmt, ap) < 0)
			(void)httpc_kill(h);
		va_end(ap);
		httpc_log_fmt(h, "\n");
	}
	if (die)
		httpc_kill(h);
	return httpc_dead(h) ? HTTPC_ERROR : ret;
}

#if HTTPC_LOGGING == 0
static inline int code(const int code) { return code; } /* suppresses warnings */
#define debug(H, ...) (code(HTTPC_OK))
#define info(H, ...)  (code(HTTPC_OK))
#define error(H, ...) (code(HTTPC_ERROR))
#define fatal(H, ...) (httpc_kill((H)))
#else
#define debug(H, ...) httpc_log_line((H), "debug", 0, HTTPC_OK,    __LINE__, __VA_ARGS__)
#define info(H, ...)  httpc_log_line((H), "info",  0, HTTPC_OK,    __LINE__, __VA_ARGS__)
#define error(H, ...) httpc_log_line((H), "error", 0, HTTPC_ERROR, __LINE__, __VA_ARGS__)
#define fatal(H, ...) httpc_log_line((H), "fatal", 1, HTTPC_ERROR, __LINE__, __VA_ARGS__)
#endif

static void *httpc_malloc(httpc_t *h, const size_t size) {
	assert(h);
	assert(h->os.allocator);
	debug(h, "allocate %ld bytes", (long)size);
	if (httpc_dead(h))
		return NULL;
	void *r = h->os.allocator(h->os.arena, NULL, 0, size);
	if (!r) {
		(void)httpc_kill(h);
		return NULL;
	}
	return memset(r, 0, size);
}

static void *httpc_realloc(httpc_t *h, void *pointer, const size_t size) {
	assert(h);
	assert(h->os.allocator);
	if (httpc_dead(h))
		return NULL;
	void *r = h->os.allocator(h->os.arena, pointer, 0, size);
	if (r == NULL && size != 0)
		(void)httpc_kill(h);
	return r;
}

static int httpc_free(httpc_t *h, void *pointer) {
	assert(h);
	assert(h->os.allocator);
	(void)h->os.allocator(h->os.arena, pointer, 0, 0);
	return HTTPC_OK;
}

static int httpc_read_char(httpc_t *h) {
	assert(h);
	size_t length = 1;
	unsigned char x = 0;
	if (h->os.read(h->socket, &x, &length) < 0)
		return -1;
	if (length != 1)
		return -1;
	return x;
}

static int buffer_free(httpc_t *h, buffer_t *b) {
	assert(h);
	int r = HTTPC_OK;
	if (!b)
		return HTTPC_OK;
	if (b->buffer) {
		if (httpc_free(h, b->buffer) < 0)
			r = HTTPC_ERROR;
	}
	memset(b, 0, sizeof *b);
	if (httpc_free(h, b) < 0)
		return HTTPC_ERROR;
	return r;
}

static buffer_t *buffer(httpc_t *h, size_t init) {
	assert(h);
	if (httpc_dead(h))
		return NULL;
	buffer_t *b = httpc_malloc(h, sizeof *b);
	if (!b)
		return NULL;
	b->buffer = httpc_malloc(h, init);
	if (!(b->buffer)) {
		(void)httpc_free(h, b);
		return NULL;
	}
	b->allocated = init;
	b->used = 0;
	memset(b->buffer, 0, init);
	return b;
}

static int buffer_add(httpc_t *h, buffer_t *b, const char *s) {
	assert(h);
	assert(b);
	assert(s);
	if (httpc_dead(h))
		return HTTPC_ERROR;
	const size_t l = strlen(s);
	const size_t ns = l + b->used + !(b->used);
	if (b->allocated < ns) {
		unsigned char *n = httpc_realloc(h, b->buffer, ns);
		if (!n)
			return HTTPC_ERROR;
		b->buffer = n;
		b->allocated = ns;
	}
	memcpy(b->buffer + b->used - !!(b->used), s, l);
	b->used = ns;
	b->buffer[b->used - 1] = '\0';
	return HTTPC_OK;
}

static inline int convert(int ch) {
	ch = toupper(ch);
	static const char m[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	for (int d = 0; d < (int)(sizeof (m) - 1); d++)
		if (ch == m[d])
			return d;
	return -1;
}

static int str_to_num(const char *s, length_t *out, const size_t max, unsigned long base) {
	assert(s);
	assert(out);
	length_t result = 0;
	int ch = s[0];
	*out = 0;
	if (!ch)
		return -1;
	size_t j = 0;
	for (j = 0; j < max && (ch = s[j]); j++) {
		const int digit = convert(ch);
		if (digit < 0)
			return -1;
		const length_t n = (length_t)digit + (result * (length_t)base);
		if (n < result)
			return -1;
		result = n;
	}
	if (ch && j < max)
		return -1;
	*out = result;
	return 0;
}

static int scan_number(const char *s, length_t *out, unsigned long base) {
	assert(s);
	assert(out);
	while (isspace(*s))
		s++;
	return str_to_num(s, out, 64, base);
}

/* URL Format is (roughly):
 *
 *  (http/https '://')? (user-info '@')? host (':' port)? ('/' path ('?' query)* ('#' fragment)?)
 *
 * The 'user-info' format is:
 *
 *     username ':' password
 *
 * Must ensure invalid characters are not present in path/domain/parsed-out-contents such
 * as spaces.
 *
 * The 'url' string is modified by putting in NUL terminating
 * characters where the separators were.  */
static int httpc_parse_url(httpc_t *h, const char *url) {
	assert(h);
	assert(url);
	if (httpc_dead(h))
		return HTTPC_ERROR;
	if (h->url) {
		httpc_free(h, h->url);
		h->url = NULL;
	}

	const size_t l = strlen(url);
	if (!(h->url = httpc_malloc(h, l + 2)))
		return HTTPC_ERROR;
	memcpy(h->url, url, l + 1);
	h->port    = 80;
	h->use_ssl = 0;

	int ch = 0;
	size_t i = 0, j = 0;
	char *u = h->url;

	for (;(ch = u[i]); i++)
		if (!isspace(ch))
			break;
	if (!ch) {
		error(h, "invalid URL: %s", url);
		goto fail;
	}

	const char http[] = "http://", https[] = "https://";

	if (l > sizeof http && !memcmp(&u[i], http, sizeof(http) - 1ul)) {
		i += sizeof(http) - 1ul;
	} else if (l > sizeof https && !memcmp(&u[i], https, sizeof(https) - 1ul)) {
		h->use_ssl = 1u;
		h->port = 443;
		i += sizeof(https) - 1ul;
	}

	char *usr = memchr(&u[i], '@', l - i);
	if (usr) {
		h->userpass = &u[i];
		i = (usr - u) + 1ul;
		*usr = '\0';
		if (!strchr(h->userpass, ':')) {
			error(h, "user-pass contains no ':': %s", h->userpass);
			goto fail;
		}
	}

	h->domain = &u[i];
	for (j = i;(ch = u[j]);j++)
		if (ch == ':' || ch == '/')
			break;
	if (j == i)
		goto fail;
	if (ch == '/') {
		memmove(&u[j + 1], &u[j], strlen(&u[j]) + 1);
		u[j] = '\0';
	}
	if (!strlen(h->domain))
		goto fail;
	if (ch == ':') {
		u[j] = '\0';
		length_t port = 0;
		for (i = j + 1; (ch = u[i]); i++)
			if (!isdigit(ch))
				break;
		if (str_to_num(&u[j + 1], &port, i - (j + 1), 10) < 0) {
			error(h, "invalid port number");
			goto fail;
		}
		h->port = port;
		j = i - 1;
	}

	h->path = &u[j + 1];
	h->path = h->path[0] ? h->path : "/";

	info(h, "domain:    %s", h->domain);
	info(h, "port:      %d", h->port);
	info(h, "SSL:       %s", h->use_ssl ? "true" : "false");
	if (h->userpass)
		info(h, "user/pass: %s", h->userpass);
	info(h, "path       %s", h->path ? h->path : "/");
	return HTTPC_OK;
fail:
	(void)httpc_free(h, h->url);
	h->url = NULL;
	return HTTPC_ERROR;
}

enum { HTTPC_GET, HTTPC_HEAD, HTTPC_PUT, HTTPC_POST, HTTPC_DELETE };

static const char *op_to_str(int op) {
	char *r = NULL;
	switch (op) {
	case HTTPC_GET:    r = "GET ";  break;
	case HTTPC_HEAD:   r = "HEAD "; break;
	case HTTPC_PUT:    r = "PUT ";  break;
	case HTTPC_POST:   r = "POST "; break;
	case HTTPC_DELETE: r = "DELETE "; break;
	}
	return r;
}

static int httpc_request_send_header(httpc_t *h, int op) {
	assert(h);
	implies(h->argc, h->argv);
	if (httpc_dead(h))
		return HTTPC_ERROR;
	const char *operation = op_to_str(op);
	if (!operation)
		return fatal(h, "unknown operation '%d'", op);
	/* TODO: We could perform some small program optimization on this by
	 * allocating on the stack then moving to heap when the size gets
	 * too big. */
	buffer_t *b = buffer(h, HTTPC_STACK_BUFFER_SIZE);
	if (!b)
		return HTTPC_ERROR;

	if (buffer_add(h, b, operation) < 0)
		goto fail;
	if (buffer_add(h, b, h->path ? h->path : "/") < 0)
		goto fail;
	if (h->os.flags & HTTPC_OPT_HTTP_1_0) {
		if (buffer_add(h, b, " HTTP/1.0\r\nHost: ") < 0)
			goto fail;
	} else {
		if (buffer_add(h, b, " HTTP/1.1\r\nHost: ") < 0)
			goto fail;
	}
	if (buffer_add(h, b, h->domain) < 0)
		goto fail;
	if (buffer_add(h, b, "\r\n") < 0)
		goto fail;
	if (op == HTTPC_GET && h->os.flags & HTTPC_OPT_HTTP_1_0 && h->position && h->accept_ranges) {
		char range[64 + 1] = { 0 };
		if (buffer_add(h, b, "Range: bytes=") < 0)
			goto fail;
		num_to_str(range, h->position, 10);
		if (buffer_add(h, b, range) < 0)
			goto fail;
		if (buffer_add(h, b, "-\r\n") < 0)
			goto fail;
	}
	if (op == HTTPC_PUT || op == HTTPC_POST) {
		if (h->length_set) {
			char content[64 + 1] = { 0 };
			if (buffer_add(h, b, "Content-Length: ") < 0)
				goto fail;
			num_to_str(content, h->length, 10);
			if (buffer_add(h, b, content) < 0)
				goto fail;
			if (buffer_add(h, b, "\r\n") < 0)
				goto fail;
		} else { /* Attempt to send chunked encoding */
			if (buffer_add(h, b, "Transfer-Encoding: chunked\r\n") < 0)
				goto fail;
		}
	}

	if (buffer_add(h, b, "Connection: Close\r\n") < 0)
		goto fail;
	if (buffer_add(h, b, "Accept-Encoding: identity\r\n") < 0)
		goto fail;
	if (h->userpass) {
		char b64[HTTPC_STACK_BUFFER_SIZE] = { 0 };
		size_t b64l = sizeof b64;
		const size_t upl = strlen(h->userpass);
		if (base64_encode((uint8_t*)h->userpass, upl, (uint8_t*)b64, &b64l) < 0) {
			error(h, "base64 encoding fail");
			goto fail;
		}
		if (buffer_add(h, b, "Authorization: Basic ") < 0)
			goto fail;
		if (buffer_add(h, b, b64) < 0)
			goto fail;
		if (buffer_add(h, b, "\r\n") < 0)
			goto fail;
	}

	if (h->os.write(h->socket, b->buffer, b->used - 1) < 0)
		goto fail;

	for (int i = 0; i < h->argc; i++) {
		const char *line = h->argv[i];
		size_t l = 0;
		for (l = 0; line[l]; l++)
			if (line[l] == '\r' || line[l] == '\n')
				return fatal(h, "invalid custom header field (illegal chars present)");
		if (h->os.write(h->socket, (unsigned char *)line, l) < 0)
			goto fail;
		if (h->os.write(h->socket, (unsigned char *)"\r\n", 2) < 0)
			goto fail;
	}

	if (h->os.write(h->socket, (unsigned char *)"\r\n", 2) < 0)
		goto fail;

	info(h, "%s request complete", operation);
	return buffer_free(h, b);
fail:
	(void)buffer_free(h, b);
	return error(h, "send GET header failed");
}

static int httpc_backoff(httpc_t *h) {
	/* instead of Xms, we could use the round trip time
	 * as estimated by the connection time as an initial guess as
	 * per RFC 2616 */
	if (httpc_dead(h))
		return HTTPC_ERROR;
	const unsigned long backoff = 500ul * (1ul << h->retries);
	const unsigned long limited = MIN(1000ul * 10ul * 1ul, backoff);
	info(h, "backing off for %lu ms, retried %u", limited, (h->retries));
	return h->os.sleep(limited);
}

/* This allows us to be a bit more liberal in what we accept */
static inline int httpc_case_insensitive_compare(const char *a, const char *b, const size_t length) {
	assert(a);
	assert(b);
	for (size_t i = 0; i < length ; i++) {
		const int ach = tolower(a[i]);
		const int bch = tolower(b[i]);
		const int diff = ach - bch;
		if (!ach || diff)
			return diff;
	}
	return 0;
}

/* NB. We could add in a callback to handle unknown fields, however we would
 * need to add infrastructure so an external user could meaningfully interact
 * with the library internals, which would be too invasive. */
static int httpc_parse_response_field(httpc_t *h, char *line, size_t length) {
	assert(h);
	assert(line);
	if (httpc_dead(h))
		return HTTPC_ERROR;
	if (length == 0)
		return HTTPC_OK;
	line[length - 1] = '\0';

#define X_MACRO_FIELDS \
	X("Transfer-Encoding:", FLD_TRANSFER_ENCODING) \
	X("Content-Length:",    FLD_CONTENT_LENGTH)\
	X("Accept-Ranges:",     FLD_ACCEPT_RANGES)\
	X("Location:",          FLD_REDIRECT)

	enum {
#define X(STR, ENUM) ENUM,
		X_MACRO_FIELDS
#undef X
	};

	static const struct field {
		const char *name;
		size_t length;
		int type;
	} fields[] = {
#define X(STR, ENUM) { .name = STR, .length = sizeof (STR) - 1, .type = ENUM },
		X_MACRO_FIELDS
#undef X
	};

	const size_t field_length = sizeof (fields) / sizeof (fields[0]);
	for (size_t i = 0; i < field_length; i++) {
		const struct field *fld = &fields[i];
		if (fld->length > length)
			continue;
		if (httpc_case_insensitive_compare(fld->name, line, fld->length))
			continue;
		switch (fld->type) {
		case FLD_ACCEPT_RANGES:
			if (strstr(line, "bytes")) {
				h->accept_ranges = !!(h->os.flags & HTTPC_OPT_HTTP_1_0);
				return info(h, "Accept-Ranges: bytes");
			}
			if (strstr(line, "none")) {
				h->accept_ranges = 0;
				return info(h, "Accept-Ranges: none");
			}
			return error(h, "unknown accept ranges field: %s", line);
		case FLD_TRANSFER_ENCODING:
			if (strchr(line, ','))
				return error(h, "Transfer encoding too complex, cannot handle it: %s", line);
			if (strstr(line, "identity")) {
				h->identity = 1;
				h->position = 0;
				return info(h, "identity transfer encoding");
			}
			if (strstr(line, "chunked")) { /* chunky monkey setting */
				h->identity = 0;
				return info(h, "chunked transfer encoding");
			}
			return error(h, "cannot handle transfer encoding: %s", line);
		case FLD_CONTENT_LENGTH:
			if (scan_number(&line[fld->length], &h->length, 10) < 0)
				return error(h, "invalid content length: %s", line);
			h->length_set = 1;
			return info(h, "Content Length: %lu", (unsigned long)h->length);
		case FLD_REDIRECT:
			if (h->response >= 300 && h->response < 399) {
				if (h->redirects++ > h->redirects_max)
					return error(h, "redirect count exceed max (%u)", (unsigned)h->redirects_max);
				size_t k = 0, j = 0;
				for (k = fld->length; isspace(line[k]); k++)
					;
				j = k;
				for (k = fld->length; !isspace(line[k]) && line[k]; k++)
					;
				line[k] = '\0';
				if (httpc_parse_url(h, &line[j]) < 0)
					return fatal(h, "redirect failed");
				h->redirect = 1;
				return info(h, "redirecting request");
			}
			return fatal(h, "invalid redirect");
		default:
			return fatal(h, "invalid state");
		}
	}
	return info(h, "unknown field: %s", line);
}

static int httpc_read_until_line_end(httpc_t *h, unsigned char *buf, size_t *length) {
	assert(h);
	assert(buf);
	assert(length);
	const size_t olength = *length;
	*length = 0;
	if (olength == 0)
		return fatal(h, "expected length > 0");
	if (httpc_dead(h))
		return HTTPC_ERROR;
	buf[olength - 1] = '\0';
	for (size_t i = 0; i < (olength - 1); i++) {
		const int ch = httpc_read_char(h);
		if (ch < 0)
			return error(h, "unexpected EOF");
		if (ch == '\r') {
			if (httpc_read_char(h) != '\n')
				return error(h, "Got '\\r' with no '\\n'");
			buf[i] = '\0';
			*length = i;
			return HTTPC_OK;
		}
		buf[i] = ch;
	}
	return fatal(h, "buffer too small");
}

static int httpc_parse_response_header_start_line(httpc_t *h, const char *line, const size_t length, char *ok, size_t okl) {
	assert(h);
	const char v1_0[] = "HTTP/1.0 ", v1_1[] = "HTTP/1.1 ";
	size_t i = 0, j = 0;
	assert(okl >= 1);

	if (length < sizeof (v1_0) && length < sizeof (v1_1))
		return error(h, "start line too small");

	if (!httpc_case_insensitive_compare(line, v1_0, sizeof (v1_0) - 1)) {
		h->v1 = 1;
		h->v2 = 0;
		i += sizeof (v1_0) - 1;
	} else if (!httpc_case_insensitive_compare(line, v1_1, sizeof (v1_1) - 1)) {
		h->v1 = 1;
		h->v2 = 1;
		i += sizeof (v1_1) - 1;
	} else {
		return error(h, "unknown HTTP protocol/version: %s", line);
	}
	while (isspace(line[i]))
		i++;
	j = i;
	while (isdigit(line[j]))
		j++;
	length_t resp = 0;
	if (str_to_num((const char *)&line[i], &resp, j - i, 10) < 0)
		return error(h, "invalid response number: %s", line);
	h->response = resp;
	while (isspace(line[j]))
		j++;
	if(j >= length)
		return error(h, "bounds exceeded");
	memcpy(ok, &line[j], MIN(okl, length - j));
	ok[okl - 1] = '\0';
	return HTTPC_OK;
}

static int httpc_parse_response_header(httpc_t *h) {
	assert(h);
	if (httpc_dead(h))
		return HTTPC_ERROR;
	char ok[128] = { 0 };
	unsigned char line[HTTPC_STACK_BUFFER_SIZE] = { 0 }; /* TODO: Reuse request buffer? */
	size_t length = 0, hlen = 0;
	h->v1 = 0;
	h->v2 = 0;
	h->response = 0;
	h->length = 0;
	h->identity = 1;
	h->length_set = 0;
	h->accept_ranges = !!(h->os.flags & HTTPC_OPT_HTTP_1_0);

	length = sizeof line;
	if (httpc_read_until_line_end(h, line, &length) < 0)
		return error(h, "protocol error (could not read first line)");
	hlen += length;
	info(h, "HEADER: %s/%lu", line, (unsigned long)length);

	if (httpc_parse_response_header_start_line(h, (const char *)line, length, ok, sizeof ok) < 0)
		return error(h, "start line parse failed");

	/* For handling redirections: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections> */
	if (h->response < 200 || h->response > 399)
		return error(h, "invalid response number: %u", h->response);
	if (h->response >= 200 && h->response <= 299) {
		if (strlen(ok) < 2 || 0 != httpc_case_insensitive_compare(ok, "OK", 2))
			return error(h, "unexpected HTTP response: %s", ok);
	}

	for (; hlen < HTTPC_MAX_HEADER; hlen += length) {
		length = sizeof line;
		if (httpc_read_until_line_end(h, line, &length) < 0)
			return error(h, "invalid header: %s", line);
		if (length == 0)
			break;
		if (httpc_parse_response_field(h, (char*)line, sizeof line) < 0)
			return error(h, "error parsing response line");
	}

	return info(h, "header done");
}

static int httpc_execute_callback(httpc_t *h, const unsigned char *buf, const size_t length) {
	assert(h);
	assert(buf);
	if (h->fn == NULL) /* null operation */
		return HTTPC_OK;
	if ((h->position + length) < h->max) /* discard previous data run */
		return HTTPC_OK;
	const size_t diff = (h->position + length) - h->max;
	assert(diff <= length);
	if (h->fn(h->fn_param, (unsigned char*)buf, diff, h->max) < 0)
		return error(h, "fn callback failed");
	return HTTPC_OK;
}

static int httpc_parse_response_body_identity(httpc_t *h) {
	assert(h);
	assert(h->identity);
	if (httpc_dead(h))
		return HTTPC_ERROR;

	for (;;) {
		unsigned char buf[HTTPC_STACK_BUFFER_SIZE];
		size_t length = sizeof buf;
		if (h->os.read(h->socket, buf, &length) < 0)
			return error(h, "read error");
		if (length == 0)
			break;
		if ((h->position + length) < h->position)
			return fatal(h, "overflow in length");
		if (httpc_execute_callback(h, buf, length) < 0)
			return HTTPC_ERROR;
		h->position += length;
		h->max = MAX(h->max, h->position);
	}
	if (h->length_set && h->position != h->length)
		return error(h, "expected %lu bytes but got %lu", (unsigned long)h->position, (unsigned long)h->length);
	return HTTPC_OK;
}

static int httpc_parse_response_body_chunked(httpc_t *h) {
	assert(h);
	assert(h->identity == 0);
	if (httpc_dead(h))
		return HTTPC_ERROR;

	for (;;) {
		unsigned char n[64+1] = { 0, };
		size_t nl = sizeof n;
		if (httpc_read_until_line_end(h, n, &nl) < 0) {
			if (h->length_set && h->length == 0)
				return info(h, "zero content length, nothing to read");
			return error(h, "unexpected EOF");
		}
		length_t length = 0;
		if (str_to_num((char*)n, &length, sizeof (n) - 1, 16) < 0)
			return error(h, "number format error: %s", n);
		if (length == 0)
			return info(h, "chunked done");

		for (size_t i = 0, l = 0; i < length; i += l) {
			unsigned char buf[HTTPC_STACK_BUFFER_SIZE];
			BUILD_BUG_ON(sizeof buf != HTTPC_STACK_BUFFER_SIZE);
			const size_t requested = MIN(sizeof (buf), length - i);
			l = requested;
			if (h->os.read(h->socket, buf, &l) < 0)
				return error(h, "read failed");
			if (httpc_execute_callback(h, buf, l) < 0)
				return HTTPC_ERROR;
			h->position += l;
			h->max = MAX(h->max, h->position);
		}
		nl = 2;
		if (h->os.read(h->socket, n, &nl) < 0)
			return HTTPC_ERROR;
		if (nl != 2 && memcmp(n, "\r\n", 2))
			return HTTPC_ERROR;
	}
	return HTTPC_OK;
}

static int httpc_parse_response_body(httpc_t *h) {
	assert(h);
	if (httpc_dead(h))
		return HTTPC_ERROR;
	if (h->identity)
		return httpc_parse_response_body_identity(h);
	return httpc_parse_response_body_chunked(h);;
}

static int httpc_generate_request_body(httpc_t *h) {
	assert(h);
	int r = HTTPC_OK;
	if (!(h->fn))
		return info(h, "no callback - nothing to do");
	int chunky = h->length_set == 0;
	for (size_t pos = 0;;) {
		unsigned char buf[HTTPC_STACK_BUFFER_SIZE];
		r = h->fn(h->fn_param, buf, sizeof buf, pos);
		if (r == 0) {
			if (chunky) {
				if (h->os.write(h->socket, (unsigned char*)"0\r\n", 3) < 0)
					r = error(h, "write failed");
			}
			break; /* done! */
		}
		if (r < 0) {
			error(h, "fn failed");
			break;
		}
		pos += r;
		if (chunky) {
			char n[64 + 1];
			assert(r < INT_MAX);
			const unsigned l = num_to_str(n, r, 16);
			if (h->os.write(h->socket, (unsigned char*)n, l) < 0) {
				r = error(h, "write failed");
				break;
			}
		}

		if (h->os.write(h->socket, buf, r) < 0) {
			r = error(h, "write failed");
			break;
		}

		if (chunky) {
			if (h->os.write(h->socket, (unsigned char*)"\r\n", 2) < 0) {
				r = error(h, "write failed");
				break;
			}
		}

		if (r < (int)sizeof buf) {
			if (chunky) {
				if (h->os.write(h->socket, (unsigned char*)"0\r\n", 3) < 0)
					r = error(h, "write failed");
			}
			break;
		}
	}
	if (r < 0)
		return error(h, "body generation failed");
	if (chunky) {
		if (h->os.write(h->socket, (unsigned char*)"0\r\n", 3) < 0)
			return error(h, "write failed");
	}
	return info(h, "body generated");
}

static inline int banner(httpc_t *h) {
	assert(h);
	USED(h);
	unsigned long version = 0;
	httpc_version(&version);
	const unsigned z = version & 0xff, y = (version >> 8) & 0xff, x = (version >> 16) & 0xff;
	const unsigned opt = (version >> 24) & 0xff;
	/* warning suppression if HTTPC_LOGGING == 0 */
	USED(version);
	USED(x);
	USED(y);
	USED(z);
	USED(opt);
	USED(httpc_log_line);
	info(h, "Project: HTTPC, embeddable HTTP client version %u.%u.%u (opts %u)", x, y, z, opt);
	info(h, "Repo:    https://github.com/howerj/httpc");
	info(h, "Author:  Richard James Howe");
	info(h, "Email:   howe.r.j.89@gmail.com");
	return info(h, "License: The Unlicense");
}

static int httpc_op(httpc_t *h, const char *url, int op) {
	assert(h);
	assert(url);
	int r = HTTPC_OK, open = 0, progress = 0;
	if (banner(h) < 0)
		return HTTPC_ERROR;
	if (h->retries_max == 0)
		h->retries_max = HTTPC_CONNECTION_ATTEMPTS;
	if (h->redirects_max == 0)
		h->retries_max = HTTPC_REDIRECT_MAX;
	if (httpc_parse_url(h, url) < 0)
		return HTTPC_ERROR;

	for (; h->retries < h->retries_max; h->retries += !progress) {
		if (httpc_dead(h))
			return fatal(h, "cannot continue quitting");
		if (h->os.open(&h->socket, &h->os, h->os.socketopts, h->domain, h->port, h->use_ssl) == HTTPC_OK) {
			open = 1;
			if (httpc_request_send_header(h, op) < 0)
				goto backoff;
			if (op == HTTPC_POST || op == HTTPC_PUT) {
				if (httpc_generate_request_body(h) < 0)
					goto backoff;
			}
			if (httpc_parse_response_header(h) < 0) {
				if (op == HTTPC_PUT || op == HTTPC_POST || op == HTTPC_DELETE) {
					if (h->response) {
						r = error(h, "request failed");
						goto end;
					}
				}
				goto backoff;
			}
			if (h->redirect) {
				(void)h->os.close(h->socket, &h->os);
				open = 0;
				h->redirect = 0;
				continue;
			}

			if (op == HTTPC_GET) {
				const length_t pos = h->position;
				progress = 0;
				if (httpc_parse_response_body(h) < 0) {
					progress = pos < h->position; /* we have processed some data...*/
					goto backoff;
				}
			}
			break;
		}
		error(h, "open failed");
backoff:
		h->redirect = 0;
		if (open) {
			(void)h->os.close(h->socket, &h->os);
			open = 0;
		}
		h->socket = NULL;
		if (httpc_backoff(h) < 0) {
			r = HTTPC_ERROR;
			goto end;
		}
	}
	if (h->retries >= HTTPC_CONNECTION_ATTEMPTS)
		r = HTTPC_ERROR;
end:
	if (open)
		if (h->os.close(h->socket, &h->os) < 0)
			r = HTTPC_ERROR;
	if (httpc_free(h, h->url) < 0)
		r = HTTPC_ERROR;
	return r;
}

int httpc_get(httpc_options_t *a, const char *url, httpc_callback fn, void *param) {
	assert(a);
	assert(url);
	httpc_t h = { .os = *a, .fn = fn, .fn_param = param, };
	return httpc_op(&h, url, HTTPC_GET);
}

/* TODO: This put is a little buggy around the input and response handling */
int httpc_put(httpc_options_t *a, const char *url, httpc_callback fn, void *param) {
	assert(a);
	assert(url);
	httpc_t h = { .os = *a, .fn = fn, .fn_param = param, };
	return httpc_op(&h, url, HTTPC_PUT);
}

int httpc_head(httpc_options_t *a, const char *url) {
	assert(a);
	assert(url);
	httpc_t h = { .os = *a, };
	return httpc_op(&h, url, HTTPC_HEAD);
}

/* TODO: Implement OPTIONS/TRACE/POST */
int httpc_delete(httpc_options_t *a, const char *url) { /* NB. A DELETE body is technically allowed... */
	assert(a);
	assert(url);
	httpc_t h = { .os = *a, };
	return httpc_op(&h, url, HTTPC_DELETE);
}

typedef struct { char *buffer; size_t length; } buffer_cb_t;

static int httpc_get_buffer_cb(void *param, unsigned char *buf, size_t length, size_t position) {
	assert(param);
	assert(buf);
	buffer_cb_t *b = param;
	if ((length + position) > b->length || (length + position) < length)
		return HTTPC_ERROR;
	memcpy(&b->buffer[position], buf, length);
	return HTTPC_OK;
}

static int httpc_put_buffer_cb(void *param, unsigned char *buf, size_t length, size_t position) {
	assert(param);
	assert(buf);
	buffer_cb_t *b = param;
	if (position > b->length)
		return HTTPC_ERROR;
	const size_t copy = MIN(length, b->length - position);
	memcpy(buf, &b->buffer[position], copy);
	assert(copy < INT_MAX);
	return copy;
}

int httpc_get_buffer(httpc_options_t *a, const char *url, char *buffer, size_t length) {
	assert(url);
	assert(a);
	assert(buffer);
	buffer_cb_t param = { .buffer = buffer, .length = length };
	httpc_t h = { .os = *a, .fn = httpc_get_buffer_cb, .fn_param = &param, };
	return httpc_op(&h, url, HTTPC_GET);
}

int httpc_put_buffer(httpc_options_t *a, const char *url, char *buffer, size_t length) {
	assert(url);
	assert(a);
	assert(buffer);
	buffer_cb_t param = { .buffer = buffer, .length = length };
	httpc_t h = { .os = *a, .fn = httpc_put_buffer_cb, .fn_param = &param, .length = length, .length_set = 1, };
	return httpc_op(&h, url, HTTPC_PUT);
}

static inline int httpc_testing_sleep(unsigned long milliseconds) {
	UNUSED(milliseconds);
	return HTTPC_OK;
}

typedef struct {
	httpc_t *h;
	const char *buffer;
	size_t length, position;
} testing_t;

static inline int httpc_testing_open(void **socket, httpc_options_t *a, void *opts, const char *domain, unsigned short port, int use_ssl) {
	assert(socket);
	assert(a);
	assert(opts);
	assert(domain);
	assert(port != 0);
	UNUSED(use_ssl);
	httpc_t *h = opts;

	static const struct sites {
		char *domain;
		char *file;
	} files[] = {
		{
			.domain = "example.com",
			.file   = "HTTP/1.1 200 OK\r\n"
				"Content-Type: text/plain\r\n"
				"Transfer-Encoding: chunked\r\n"
				"\r\n"
				"7\r\nMozilla\r\n"
				"9\r\nDeveloper\r\n"
				"7\r\nNetwork\r\n"
				"4\r\nWiki\r\n"
				"5\r\npedia\r\n"
				"E\r\n in\r\n\r\nchunks.\r\n"
				"0\r\n",
		},
		{
			.domain = "redirect.com",
			.file = "HTTP/1.1 301 Moved Permanently\r\nLocation: example.com\r\n\r\n",
		},
		{
			.domain = "identity.com",
			.file = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789",
		}
	};
	const size_t files_count = sizeof (files) / sizeof (files[0]);
	for (size_t i = 0; i < files_count; i++) {
		if (!strcmp(domain, files[i].domain)) {
			testing_t *t = httpc_malloc(h, sizeof *t);
			if (!t)
				return fatal(h, "unable to malloc");
			t->h = h;
			t->buffer = files[i].file;
			t->length = strlen(t->buffer);
			t->position = 0;
			*socket = t;
			return HTTPC_OK;
		}
	}

	return HTTPC_ERROR;
}

static inline int httpc_testing_close(void *socket, httpc_options_t *a) {
	assert(a);
	assert(socket);
	testing_t *t = socket;
	return httpc_free(t->h, t);
}

static inline int httpc_testing_read(void *socket, unsigned char *buf, size_t *length) {
	assert(socket);
	assert(buf);
	assert(length);
	testing_t *t = socket;
	size_t requested = *length;
	*length = 0;
	if (t->position >= t->length)
		return HTTPC_OK;
	size_t copy = MIN(requested, t->length - t->position);
	memcpy(buf, &t->buffer[t->position], copy);
	t->position += copy;
	*length = copy;
	return HTTPC_OK;
}

static inline int httpc_testing_write(void *socket, const unsigned char *buf, size_t length) {
	assert(socket);
	assert(buf);
	UNUSED(length);
	return HTTPC_OK; /* discard for now */
}

int httpc_tests(httpc_options_t *a) {
	assert(a);
	BUILD_BUG_ON(HTTPC_STACK_BUFFER_SIZE < 128ul);
	BUILD_BUG_ON(HTTPC_CONNECTION_ATTEMPTS < 1ul);
	BUILD_BUG_ON(HTTPC_MAX_HEADER < 1024ul && HTTPC_MAX_HEADER != 0ul);

	if (HTTPC_TESTS_ON == 0)
		return HTTPC_OK;

	a->open  = httpc_testing_open;
	a->close = httpc_testing_close;
	a->read  = httpc_testing_read;
	a->write = httpc_testing_write;
	a->sleep = httpc_testing_sleep;

	static const struct url_test {
		char *url;
		char *domain /* or IPv4/IPv6 */, *userpass, *path;
		unsigned short port;
		int use_ssl, error;
	} url_tests[] = {
		{ .url = "example.com",                                  .domain = "example.com",   .userpass = NULL,            .path = "/",           .port = 80,  .use_ssl = 0, .error = 0, },
		{ .url = "example.co.uk",                                .domain = "example.co.uk", .userpass = NULL,            .path = "/",           .port = 80,  .use_ssl = 0, .error = 0, },
		{ .url = "user:password@example.com",                    .domain = "example.com",   .userpass = "user:password", .path = "/",           .port = 80,  .use_ssl = 0, .error = 0, },
		{ .url = "user:password@example.com:666",                .domain = "example.com",   .userpass = "user:password", .path = "/",           .port = 666, .use_ssl = 0, .error = 0, },
		{ .url = "http://example.com",                           .domain = "example.com",   .userpass = NULL,            .path = "/",           .port = 80,  .use_ssl = 0, .error = 0, },
		{ .url = "https://example.com",                          .domain = "example.com",   .userpass = NULL,            .path = "/",           .port = 443, .use_ssl = 1, .error = 0, },
		{ .url = "https://example.com:666",                      .domain = "example.com",   .userpass = NULL,            .path = "/",           .port = 666, .use_ssl = 1, .error = 0, },
		{ .url = "https://example.com:666/",                     .domain = "example.com",   .userpass = NULL,            .path = "/",           .port = 666, .use_ssl = 1, .error = 0, },
		{ .url = "https://example.com:666/index.html",           .domain = "example.com",   .userpass = NULL,            .path = "/index.html", .port = 666, .use_ssl = 1, .error = 0, },
		{ .url = "https://example.com/",                         .domain = "example.com",   .userpass = NULL,            .path = "/",           .port = 443, .use_ssl = 1, .error = 0, },
		{ .url = "https://example.com/index.html",               .domain = "example.com",   .userpass = NULL,            .path = "/index.html", .port = 443, .use_ssl = 1, .error = 0, },
		{ .url = "https://user:password@example.com/index.html", .domain = "example.com",   .userpass = "user:password", .path = "/index.html", .port = 443, .use_ssl = 1, .error = 0, },
		{ .url = "",                                             .domain = "",              .userpass = "",              .path = "",            .port = 0,   .use_ssl = 0, .error = 1, },
		{ .url = "https://user@password:example.com/index.html", .domain = "",              .userpass = "",              .path = "",            .port = 0,   .use_ssl = 0, .error = 1, },
	};

	/* TODO: Check for memory leaks in failure cases */
	int r = HTTPC_OK;
	const size_t url_tests_count = sizeof (url_tests) / sizeof (url_tests[0]);
	for (size_t i = 0; i < url_tests_count; i++) {
		httpc_t h = { .os = *a, };

		const struct url_test *u = &url_tests[i];
		info(&h, "URL:       %s", u->url);
		const int rp = httpc_parse_url(&h, u->url);
		if (rp < 0) {
			if (u->error == 0)
				r = error(&h, "HTTP URL parsing failed");
			else
				info(&h, "expected and got an error");
			continue;
		}
		if (u->error) {
			r = error(&h, "expected an error and got none");
			continue;
		}
		if (strcmp(u->path, h.path))
			r = error(&h, "path mismatch:   '%s' != '%s'", u->path, h.path);
		if (strcmp(u->domain, h.domain))
			r = error(&h, "domain mismatch: '%s' != '%s'", u->domain, h.domain);
		if (u->port != h.port)
			r = error(&h, "port mismatch:   '%u' != '%u'", (unsigned) u->port, (unsigned) h.port);
		if (u->use_ssl != h.use_ssl)
			r = error(&h, "SSL mismatch:    '%u' != '%u'", (unsigned) u->use_ssl, (unsigned) h.use_ssl);
		if (u->userpass) {
			if (h.userpass == NULL) {
				r = error(&h, "user-pass mismatch: '%s' != NULL", u->userpass);
			} else {
				if (strcmp(u->userpass, h.userpass))
					r = error(&h, "user-pass mismatch: '%s' != '%s'", u->userpass, h.userpass);
			}
		}
		if (httpc_free(&h, h.url) < 0)
			r = HTTPC_ERROR;
		h.url = NULL;
	}

	static const struct file_test {
		const char *file;
		int error;
	} file_tests[] = {
		{ "example.com",   0, },
		{ "identity.com",  0, },
		{ "redirect.com",  0, },
		/* TODO: Test failure cases */
	};
	const size_t file_tests_count = sizeof (file_tests) / sizeof (file_tests[0]);
	for (size_t i = 0; i < file_tests_count; i++) {
		const struct file_test *ft = &file_tests[i];
		httpc_t h = { .os = *a, };
		a->socketopts = &h;
		info(&h, "Test GET on URL '%s'", ft->file);
		if (httpc_get(a, ft->file, NULL, NULL) < 0)
			r = error(&h, "Test GET on URL '%s' failed", ft->file);
		a->socketopts = NULL;
	}
	return r;
}

