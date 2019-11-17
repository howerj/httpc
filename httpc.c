/* Project:    Embeddable HTTP 1.0/1.1 Client
 * Author:     Richard James Howe
 * License:    The Unlicense
 * Email:      howe.r.j.89@gmail.com
 * Repository: https://github.com/howerj/httpc */

/* TODO:
 * - Export some the utility functions
 * - Allow custom headers, HTTP-1.0 only and GET/HEAD/PUT/DELETE/POST
 * - Implement non-blocking!  */

#include "httpc.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h> /* file operations not used, but sscanf is */
#include <stdint.h>
#include <ctype.h>

#ifndef HTTPC_STACK_BUFFER_SIZE /* buffers allocated on the stack, responsible for some arbitrary limits as well. */
#define HTTPC_STACK_BUFFER_SIZE (512ul)
#endif

#ifndef HTTPC_VERSION
#define HTTPC_VERSION (0x000000ul) /* all zeros = built incorrectly */
#endif

#ifndef HTTPC_TESTS_ON /* Build in tests to the program */
#define HTTPC_TESTS_ON (1ul)
#endif

#ifndef HTTPC_CONNECTION_ATTEMPTS
#define HTTPC_CONNECTION_ATTEMPTS (3ul)
#endif

#ifndef HTTPC_RETRY_COUNT
#define HTTPC_RETRY_COUNT (3ul)
#endif

#ifndef HTTPC_REDIRECT_MAX
#define HTTPC_REDIRECT_MAX (3ul)
#endif

#ifndef HTTPC_MAX_HEADER /* maximum size for the header; 0 == infinite length allowed */
#define HTTPC_MAX_HEADER (4096ul)
#endif

#define UNUSED(X) ((void)(X))
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#define BUILD_BUG_ON(condition)   ((void)sizeof(char[1 - 2*!!(condition)]))
#define implies(P, Q)             assert(!(P) || (Q))

typedef struct {
	unsigned char *buffer;
	size_t allocated, used;
} buffer_t;

typedef unsigned long length_t;

struct httpc {
	httpc_os_t os;
	httpc_callback fn;
	void *fn_param;
	/* These strings point into 'url', which has been modified from the
	 * original URL to contain a bunch of NUL terminated strings where the
	 * delimiters were */
	char *domain /* or IPv4/IPv6 */, *userpass, *path;
	void *socket;
	char *url;
	length_t position, length, max;
	unsigned retries, redirects; /* retry count, redirect count */
	unsigned response, v1, v2; /* HTTP response, HTTP version (1.0 or 1.1) */
	unsigned short port;
	unsigned use_ssl  :1, /* if set then SSL should be used on the connection */
		 fatal    :1, /* if set then something has gone fatally wrong */
		 http1_0  :1, /* request HTTP 1.0 only, still can deal with HTTP 1.1 response however */
		 identity :1; /* 1 == identity encoded, 0 == chunked */
};

/* Modified from: <https://stackoverflow.com/questions/342409>
 * - Output buffer is NUL terminated on a successful encoding
 * - Returned output length is equivalent to strlen(out)
 * - Returns negative on error, zero on success. */
static int base64_encode(const unsigned char *in, const size_t input_length, unsigned char *out, size_t *output_length) { /* EXPORT */
	assert(in);
	assert(out);
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

int httpc_version(unsigned long *version) {
	assert(version);
	unsigned long spec = 0;
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

/* TODO: Remove error checking in rest of program, print out line number, and
 * make 'info' / 'warning'/ 'error' versions of this file. */
static int httpc_log(httpc_t *h, const char *fmt, ...) {
	assert(fmt);
	va_list ap;
	va_start(ap, fmt);
	const int r = httpc_logger(h->os.logfile, fmt, ap);
	va_end(ap);
	if (r < 0)
		return httpc_kill(h);
	return r;
}

static void *httpc_malloc(httpc_t *h, const size_t size) {
	assert(h);
	assert(h->os.allocator);
	if (httpc_dead(h))
		return NULL;
	void *r = h->os.allocator(h->os.arena, NULL, 0, size);
	if (!r)
		(void)httpc_kill(h);
	return r;
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

/* TODO: Get rid of this buffer interface / do small program optimization like
 * in pickle where small buffers are allocated on the stack */
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

static int buffer_add(httpc_t *h, buffer_t *b, char *s) {
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
static int httpc_parse_url(httpc_t *h, const char *url) { /* TODO: Cleanup/simplify this function */
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
		(void)httpc_log(h, "invalid URL: %s", url);
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
			httpc_log(h, "user-pass contains no ':': %s", h->userpass);
			goto fail;
		}
	}

	h->domain = &u[i];
	for (j = i;(ch = u[j]);j++)
		if (ch == ':' || ch == '/')
			break;
	if (j == i)
		goto fail;
	if (ch) {
		memmove(&u[j + 1], &u[j], strlen(&u[j]) + 1);
		u[j] = '\0'; /*TODO: Does not work - need to copy URL *OR* allocate one more byte and memmove */
	}
	if (!strlen(h->domain))
		goto fail;
	if (ch == ':') {
		h->port = atoi(&u[j + 1]); /* TODO: Error checking / use custom function */
		for (i = j + 1; (ch = u[i]); i++)
			if (!isdigit(ch))
				break;
	}

	h->path = &u[j + 1];
	h->path = h->path[0] ? h->path : "/";

	if (httpc_log(h, "domain:    %s", h->domain) < 0)
		goto fail;
	if (httpc_log(h, "port:      %d", h->port) < 0)
		goto fail;
	if (httpc_log(h, "SSL:       %s", h->use_ssl ? "true" : "false") < 0)
		goto fail;
	if (h->userpass)
		httpc_log(h, "user/pass: %s", h->userpass);
	if (httpc_log(h, "path       %s", h->path ? h->path : "/") < 0)
		return HTTPC_ERROR;
	return HTTPC_OK;
fail:
	(void)httpc_free(h, h->url);
	h->url = NULL;
	return HTTPC_ERROR;
}

static int httpc_request_get_send(httpc_t *h) {
	assert(h);
	if (httpc_dead(h))
		return HTTPC_ERROR;
	buffer_t *b = buffer(h, 1024); /* TODO: Fix this */
	if (!b)
		return HTTPC_ERROR;
	if (buffer_add(h, b, "GET ") < 0)
		goto fail;
	if (buffer_add(h, b, h->path ? h->path : "/") < 0)
		goto fail;
	if (h->http1_0) {
		if (buffer_add(h, b, " HTTP/1.0\r\nHost: ") < 0)
			goto fail;
	} else {
		if (buffer_add(h, b, " HTTP/1.1\r\nHost: ") < 0)
			goto fail;
	}
	if (buffer_add(h, b, h->domain) < 0)
		goto fail;
	if (h->http1_0 == 0 && h->position) {
		char range[96] = { 0 };
		if (snprintf(range, sizeof range, "\r\nRange: bytes=%lu-\r\n", (unsigned long)h->position) < 0)
			goto fail;
		if (buffer_add(h, b, range) < 0)
			goto fail;
	} else {
		if (buffer_add(h, b, "\r\n") < 0)
			goto fail;
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
			(void)httpc_log(h, "base64 encoding fail");
			goto fail;
		}
		if (buffer_add(h, b, "Authorization: Basic ") < 0)
			goto fail;
		if (buffer_add(h, b, b64) < 0)
			goto fail;
		if (buffer_add(h, b, "\r\n") < 0)
			goto fail;
	}

	if (buffer_add(h, b, "\r\n") < 0)
		goto fail;
	if (httpc_log(h, "request {\n%s}", b->buffer) < 0)
		goto fail;
	if (h->os.write(h->socket, b->buffer, b->used - 1) < 0)
		goto fail;

	return buffer_free(h, b);
fail:
	(void)httpc_log(h, "send GET header failed");
	(void)buffer_free(h, b);
	return HTTPC_ERROR;
}

static int httpc_backoff(httpc_t *h) {
	/* instead of 5000ms, we could use the round trip time
	 * as estimated by the connection time as an initial guess as
	 * per RFC 2616 */
	if (httpc_dead(h))
		return HTTPC_ERROR;
	const unsigned long backoff = 5000ul * (1ul << h->retries);
	const unsigned long limited = MIN(1000ul * 60ul * 1ul, backoff);
	httpc_log(h, "backing off for %lu ms", limited);
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

static int str_to_num(const char *s, length_t *out) { /* EXPORT */
	assert(s);
	assert(out);
	length_t result = 0;
	int ch = s[0];
	*out = 0;
	if (!ch)
		return -1;
	for (size_t j = 0; j < 64 && (ch = s[j]); j++) {
		const int digit = ch - '0';
		if (digit < 0 || digit > 9)
			return -1;
		const length_t n = digit + (result * (length_t)10ul);
		if (n < result)
			return -1;
		result = n;
	}
	if (ch)
		return -1;
	*out = result;
	return 0;
}

static int scan_number(const char *s, length_t *out) {
	assert(s);
	assert(out);
	while (isspace(*s))
		s++;
	return str_to_num(s, out);
}

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
		case FLD_TRANSFER_ENCODING:
			if (strchr(line, ',')) {
				(void)httpc_log(h, "Transfer encoding too complex, cannot handle it: %s", line);
				return HTTPC_ERROR;
			}
			if (strstr(line, "identity")) {
				if (httpc_log(h, "Identity mode") < 0)
					return HTTPC_ERROR;
				h->identity = 1;
				h->position = 0;
				return HTTPC_OK;
			}
			if (strstr(line, "chunked")) {
				if (httpc_log(h, "CHUNKY!") < 0)
					return HTTPC_ERROR;
				h->identity = 0;
				return HTTPC_OK;
			}
			(void)httpc_log(h, "Cannot handle transfer encoding: %s", line);
			return HTTPC_ERROR;
		case FLD_CONTENT_LENGTH:
			if (scan_number(&line[fld->length], &h->length) < 0) {
				(void)httpc_log(h, "Invalid content length: %s", line);
				return HTTPC_ERROR;
			}
			if (httpc_log(h, "Content Length: %lu", (unsigned long)h->length) < 0)
				return HTTPC_ERROR;
			return HTTPC_OK;
		case FLD_REDIRECT:
			if (h->response >= 300 && h->response < 399) {
				if (h->redirects++ > HTTPC_REDIRECT_MAX)
					return HTTPC_ERROR;
				size_t i = 0, j = 0;
				for (i = fld->length; isspace(line[i]); i++)
					;
				j = i;
				for (i = fld->length; !isspace(line[i]) && line[i]; i++)
					;
				line[i] = '\0';
				if (httpc_parse_url(h, &line[j]) < 0) {
					(void)httpc_log(h, "fatal - redirect failed");
					return httpc_kill(h);
				}
				if (h->retries) /* Might want to hold off back-off later */
					h->retries--;
				return HTTPC_ERROR; /* return an error to retrigger the download with a new URL */
			} else {
				(void)httpc_log(h, "invalid redirect response");
			}
			return HTTPC_ERROR;
		default:
			return HTTPC_ERROR;
		}
	}
	httpc_log(h, "unknown field: %s", line);
	return HTTPC_OK;
}

static int httpc_read_until_line_end(httpc_t *h, unsigned char *buf, size_t *length) {
	assert(h);
	assert(buf);
	assert(length);
	const size_t olength = *length;
	*length = 0;
	if (olength == 0) {
		(void)httpc_log(h, "expected length > 0");
		return HTTPC_ERROR;
	}
	buf[olength - 1] = '\0';
	size_t i = 0;
	for (i = 0; i < (olength - 1); i++) {
		const int ch = httpc_read_char(h);
		if (ch < 0) {
			(void)httpc_log(h, "unexpected EOF");
			return HTTPC_ERROR;
		}
		if (ch == '\r') { 
			if (httpc_read_char(h) != '\n') {
				(void)httpc_log(h, "Got '\\r' with no '\\n'");
				return HTTPC_ERROR;
			}
			buf[i] = '\0';
			*length = i;
			return HTTPC_OK;
		} 
		buf[i] = ch;
	}
	(void)httpc_log(h, "buffer too small");
	return HTTPC_ERROR;
}

static int httpc_parse_response_header(httpc_t *h) {
	assert(h);
	if (httpc_dead(h))
		return HTTPC_ERROR;
	unsigned char line[HTTPC_STACK_BUFFER_SIZE] = { 0 };
	size_t length = 0, hlen = 0;
	h->v1 = 0;
	h->v2 = 0;
	h->response = 0;
	h->length = 0;
	h->identity = 1;

	length = sizeof line;
	if (httpc_read_until_line_end(h, line, &length) < 0) {
		(void)httpc_log(h, "Protocol error (could not read first line)");
		return HTTPC_ERROR;
	}
	hlen += length;
	httpc_log(h, "HEADER: %s/%lu", line, (unsigned long)length);

	char ok[128] = { 0 };
	const int sr = sscanf((char*)line, "HTTP/%u.%u %u %127s", &h->v1, &h->v2, &h->response, ok); /* TODO: Replace sscanf usage? */
	if (sr != 4 || h->v1 != 1u || (h->v2 != 1u && h->v2 != 0u)) {
		(void)httpc_log(h, "invalid protocol %u/%u/%d", h->v1, h->v2, sr);
		goto fail;
	}
	ok[sizeof (ok) - 1] = '\0';
	/* For handling redirections: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections> */
	if (h->response < 200 || h->response > 399) {
		(void)httpc_log(h, "invalid response/cannot deal with response code: %u", h->response);
		httpc_kill(h);
		goto fail;
	}
	if (h->response >= 200 && h->response <= 299) {
		if (strlen(ok) > 2 || 0 != httpc_case_insensitive_compare(ok, "OK", 2)) {
			(void)httpc_log(h, "unexpected HTTP response: %s", ok);
			goto fail;
		}
	}

	for (; hlen < HTTPC_MAX_HEADER; hlen += length) {
		length = sizeof line;
		if (httpc_read_until_line_end(h, line, &length) < 0) {
			(void)httpc_log(h, "Invalid header: %s", line);
			goto fail;
		}

		if (length == 0)
			break;

		if (httpc_parse_response_field(h, (char*)line, sizeof line) < 0) {
			(void)httpc_log(h, "Error parsing response line");
			goto fail;
		}
	}

	httpc_log(h, "header done");
	return HTTPC_OK;
fail:
	return HTTPC_ERROR;
}

/* TODO: Discard content up to old position if appropriate for chunked and identity */
static int httpc_parse_response_body_identity(httpc_t *h) {
	assert(h);
	assert(h->identity);
	for (;;) {
		unsigned char buf[HTTPC_STACK_BUFFER_SIZE];
		size_t length = sizeof buf;
		if (h->os.read(h->socket, buf, &length) < 0) {
			(void)httpc_log(h, "read error");
			return HTTPC_ERROR;
		}
		if (length == 0)
			break;

		if ((h->position + length) < h->position) {
			(void)httpc_log(h, "overflow in length");
			return httpc_kill(h);
		}
	
		h->fn(h->fn_param, buf, length, h->position);
		h->position += length;
		h->position = MAX(h->max, h->position);
		//if (length < sizeof buf)
		//	break;
	}

	return HTTPC_OK;
}

static int httpc_parse_response_body_chunked(httpc_t *h) {
	assert(h);
	assert(h->identity == 0);

	for (;;) {
		unsigned char n[64+1] = { 0 };
		size_t nl = sizeof n;
		if (httpc_read_until_line_end(h, n, &nl) < 0) /* TODO: Allow it to succeed here if nothing read in? */
			return HTTPC_ERROR;
		length_t length = 0;
		if (str_to_num((char*)n, &length) < 0) {
			(void)httpc_log(h, "number format error: %s", n);
			return HTTPC_ERROR;
		}
		if (length == 0) {
			if (httpc_log(h, "chunked done done") < 0)
				return HTTPC_ERROR;
			return HTTPC_OK;
		}

		for (size_t i = 0; i < length; i += HTTPC_STACK_BUFFER_SIZE) {
			unsigned char buf[HTTPC_STACK_BUFFER_SIZE];
			BUILD_BUG_ON(sizeof buf != HTTPC_STACK_BUFFER_SIZE);
			const size_t requested = MIN(sizeof (buf), length - i);
			size_t l = requested;
			if (h->os.read(h->socket, buf, &l) < 0) {
				(void)httpc_log(h, "read failed");
				return HTTPC_ERROR;
			}
			if (l != requested) {
				(void)httpc_log(h, "read - got less than requested");
				return HTTPC_ERROR;
			}
			if (h->fn(h->fn_param, buf, requested, h->position) < 0) {
				(void)httpc_log(h, "fn callback failed");
				return HTTPC_ERROR;
			}
			h->position += requested;
			h->position = MAX(h->max, h->position);
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

int httpc_get(const char *url, httpc_os_t *a, httpc_callback fn, void *param) {
	assert(url);
	assert(a);
	assert(fn);
	UNUSED(param);
	httpc_t h = { .os = *a, .fn = fn, .fn_param = param, };
	int r = HTTPC_OK;

	/*TODO Reorganize this function and internals so that it can handle
	 * GET/PUT/DELETE/... */

	if (httpc_parse_url(&h, url) < 0)
		return HTTPC_ERROR;

	for (int open = 0; h.retries < HTTPC_CONNECTION_ATTEMPTS; h.retries++) {
		if (httpc_dead(&h)) {
			(void)httpc_log(&h, "fatal error - quitting"); /* TODO minimize the number of error strings */
			return HTTPC_ERROR;
		}
		if (h.os.open(&h.socket, h.os.socketopts, h.domain, h.port, h.use_ssl) == HTTPC_OK) {
			open = 1;
			if (httpc_request_get_send(&h) < 0)
				goto backoff;
			if (httpc_parse_response_header(&h) < 0)
				goto backoff;
			if (httpc_parse_response_body(&h) < 0)
				goto backoff;
			break;
		} else {
			(void)httpc_log(&h, "open failed");
		}
		open = 0;
backoff:
		if (open)
			(void)h.os.close(h.socket);
		h.socket = NULL;
		if (httpc_backoff(&h) < 0) {
			r = HTTPC_ERROR;
			goto end;
		}
	}
	if (h.retries >= HTTPC_CONNECTION_ATTEMPTS)
		r = HTTPC_ERROR;
end:
	if (h.os.close(h.socket) < 0)
		r = HTTPC_ERROR;
	if (httpc_free(&h, h.url) < 0)
		r = HTTPC_ERROR;
	return r;
}

/* NOTE: Probably not needed if we allow users to add custom things to a
 * header, and a custom operation {GET, PUT, DELETE, ...}. The API needs
 * rethinking so the most common options in an embedded system are easy (that
 * is read/saving to a block of memory and/or using a callback instead). */
int httpc_put(const char *url, httpc_os_t *a, httpc_callback fn, void *param) {
	assert(url);
	assert(a);
	assert(fn);
	UNUSED(param);
	return HTTPC_ERROR;
}

/* We could do a series of tests by replacing the callbacks with 
 * functions that send expected response data. */
int httpc_tests(httpc_os_t *a) {
	assert(a);
	BUILD_BUG_ON(HTTPC_STACK_BUFFER_SIZE < 128ul);
	BUILD_BUG_ON(HTTPC_CONNECTION_ATTEMPTS < 1ul);
	BUILD_BUG_ON(HTTPC_MAX_HEADER < 1024ul && HTTPC_MAX_HEADER != 0ul);

	if (HTTPC_TESTS_ON == 0)
		return HTTPC_OK;

	typedef struct {
		char *url;
		char *domain /* or IPv4/IPv6 */, *userpass, *path;
		unsigned short port;
		int use_ssl;
	} url_tests_t;

	static const url_tests_t ut[] = {
		{ .url = "example.com",                     .domain = "example.com",  .userpass = NULL,  .path = "/",            .port = 80,   .use_ssl = 0 },
		{ .url = "http://example.com",              .domain = "example.com",  .userpass = NULL,  .path = "/",            .port = 80,   .use_ssl = 0 },
		{ .url = "https://example.com",             .domain = "example.com",  .userpass = NULL,  .path = "/",            .port = 443,  .use_ssl = 1 },
		{ .url = "https://example.com/",            .domain = "example.com",  .userpass = NULL,  .path = "/",            .port = 443,  .use_ssl = 1 },
		{ .url = "https://example.com/index.html",  .domain = "example.com",  .userpass = NULL,  .path = "/index.html",  .port = 443,  .use_ssl = 1 },
		{ .url = "https://user:password@example.com/index.html",  .domain = "example.com",  .userpass = "user:password",  .path = "/index.html",  .port = 443,  .use_ssl = 1 },
	};

	httpc_t h = {
		.os = *a,
	};

	int r = HTTPC_OK;
	const size_t utl = sizeof (ut) / sizeof (ut[0]);
	for (size_t i = 0; i < utl; i++) {
		const url_tests_t *u = &ut[i];
		(void)httpc_log(&h, "URL:       %s", u->url);
		if (httpc_parse_url(&h, u->url) < 0) {
			(void)httpc_log(&h, "HTTP URL parsing failed");
			continue;
		}

		if (strcmp(u->path, h.path)) {
			(void)httpc_log(&h, "path mismatch:   '%s' != '%s'", u->path, h.path);
			r = HTTPC_ERROR;
		}
		if (strcmp(u->domain, h.domain)) {
			(void)httpc_log(&h, "domain mismatch: '%s' != '%s'", u->domain, h.domain);
			r = HTTPC_ERROR;
		}
		if (u->port != h.port) {
			(void)httpc_log(&h, "port mismatch:   '%u' != '%u'", (unsigned) u->port, (unsigned) h.port);
			r = HTTPC_ERROR;
		}
		if (u->use_ssl != h.use_ssl) {
			(void)httpc_log(&h, "SSL mismatch:    '%u' != '%u'", (unsigned) u->use_ssl, (unsigned) h.use_ssl);
			r = HTTPC_ERROR;
		}

		if (u->userpass) {
			if (h.userpass == NULL) {
				(void)httpc_log(&h, "user-pass mismatch: '%s' != NULL", u->userpass);
				r = HTTPC_ERROR;
			} else {
				if (strcmp(u->userpass, h.userpass)) {
					(void)httpc_log(&h, "user-pass mismatch: '%s' != '%s'", u->userpass, h.userpass);
					r = HTTPC_ERROR;
				}
			}
		}
	}

	return r;
}

