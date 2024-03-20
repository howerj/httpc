/* Project:    Embeddable HTTP 1.0/1.1 Client
 * Author:     Richard James Howe
 * License:    The Unlicense
 * Email:      howe.r.j.89@gmail.com
 * Repository: https://github.com/howerj/httpc
 *
 * Example driver for library. */

#include "httpc.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define UNUSED(X) ((void)(X))

typedef struct {
	size_t position;
	FILE *output;
} httpc_dump_t;

typedef struct {
	char *arg;   /* parsed argument */
	int error,   /* turn error reporting on/off */
	    index,   /* index into argument list */
	    option,  /* parsed option */
	    reset;   /* set to reset */
	char *place; /* internal use: scanner position */
	int  init;   /* internal use: initialized or not */
} httpc_getopt_t;    /* getopt clone; with a few modifications */

#ifdef _WIN32 /* Used to unfuck file mode for "Win"dows. Text mode is for losers. */
#include <windows.h>
#include <io.h>
#include <fcntl.h>
static void binary(FILE *f) { _setmode(_fileno(f), _O_BINARY); } /* only platform specific code... */
#else
static inline void binary(FILE *f) { UNUSED(f); }
#endif

/* Adapted from: <https://stackoverflow.com/questions/10404448> */
static int httpc_getopt(httpc_getopt_t *opt, const int argc, char *const argv[], const char *fmt) {
	assert(opt);
	assert(fmt);
	assert(argv);
	enum { BADARG_E = ':', BADCH_E = '?', };

	if (!(opt->init)) {
		opt->place = ""; /* option letter processing */
		opt->init  = 1;
		opt->index = 1;
	}

	if (opt->reset || !*opt->place) { /* update scanning pointer */
		opt->reset = 0;
		if (opt->index >= argc || *(opt->place = argv[opt->index]) != '-') {
			opt->place = "";
			return -1;
		}
		if (opt->place[1] && *++opt->place == '-') { /* found "--" */
			opt->index++;
			opt->place = "";
			return -1;
		}
	}

	const char *oli = NULL; /* option letter list index */
	if ((opt->option = *opt->place++) == ':' || !(oli = strchr(fmt, opt->option))) { /* option letter okay? */
		 /* if the user didn't specify '-' as an option, assume it means -1.  */
		if (opt->option == '-')
			return -1;
		if (!*opt->place)
			opt->index++;
		if (opt->error && *fmt != ':')
			(void)fprintf(stderr, "illegal option -- %c\n", opt->option);
		return BADCH_E;
	}

	if (*++oli != ':') { /* don't need argument */
		opt->arg = NULL;
		if (!*opt->place)
			opt->index++;
	} else {  /* need an argument */
		if (*opt->place) { /* no white space */
			opt->arg = opt->place;
		} else if (argc <= ++opt->index) { /* no arg */
			opt->place = "";
			if (*fmt == ':')
				return BADARG_E;
			if (opt->error)
				(void)fprintf(stderr, "option requires an argument -- %c\n", opt->option);
			return BADCH_E;
		} else	{ /* white space */
			opt->arg = argv[opt->index];
		}
		opt->place = "";
		opt->index++;
	}
	return opt->option; /* dump back option letter */
}

static void *httpc_allocator(void *arena, void *ptr, const size_t oldsz, const size_t newsz) {
	UNUSED(arena);
	if (newsz == 0) {
		free(ptr);
		return NULL;
	}
	if (newsz > oldsz)
		return realloc(ptr, newsz);
	return ptr;
}

static int httpc_dump_cb(void *param, unsigned char *buf, size_t length, size_t position) {
	assert(param);
	assert(buf);
	httpc_dump_t *d = param;
	const size_t l = position + length;
	if (l < position)
		return HTTPC_ERROR;
	d->position = position + length;
	if (fwrite(buf, 1, length, d->output) != length)
		return HTTPC_ERROR;
	return HTTPC_OK;
}

static int httpc_put_cb(void *param, unsigned char *buf, size_t length, size_t position) {
	assert(param);
	UNUSED(position);
	FILE *in = param;
	if (length == 0)
		return HTTPC_ERROR;
	const size_t l = fread(buf, 1, length, in);
	if (l < length)
		return ferror(in) ? HTTPC_ERROR : (int)l;
	return l;
}

static int help(FILE *out, const char *arg0) {
	assert(out);
	assert(arg0);
	const char *fmt = "\
Usage:      %s -[ht1vy] -u www.example.com/index.html\n\n\
Project:    Embeddable HTTP(S) Client\n\
Author:     Richard James Howe\n\
Email:      <mailto:howe.r.j.89@gmail.com>\n\
License:    The Unlicense\n\
Repository: <https://github.com/howerj/httpc>\n\
Version:    %s\n\
Options:\n\n\
\t-o #\tset operation GET/HEAD/PUT/DELETE\n\
\t-h\tprint help and exit successfully\n\
\t-t\trun the built in tests, returning failure status (0 = pass)\n\
\t-u URL\tset URL to use\n\
\t-1\tperform HTTP 1.0 request, not a HTTP 1.1 request\n\
\t-v\tturn logging on\n\
\t-y\tturn yielding on, for debugging only\n\
\t-H #\tAdd custom header, use with caution\n\
\tURL\tset URL to use\n\
\n\
Returns non zero value on failure. stdin(3) for input, stdout(3)\n\
for output, and stderr(3) for logging\n\n";
	return fprintf(out, fmt, arg0, HTTPC_VERSION);
}

enum { OP_GET, OP_HEAD, OP_PUT, OP_POST, OP_DELETE, OP_TRACE, OP_OPTIONS, };

static int operation(const char *s) {
	assert(s);
	static const char *os[] = {
		[OP_GET]     = "GET",
		[OP_HEAD]    = "HEAD",
		[OP_PUT]     = "PUT",
		[OP_POST]    = "POST",
		[OP_DELETE]  = "DELETE",
		[OP_TRACE]   = "TRACE",
		[OP_OPTIONS] = "OPTIONS",
	};
	for (size_t i = 0; i < sizeof (os) / sizeof (os[0]); i++)
		if (!strcmp(s, os[i]))
			return i;
	return -1;
}

static int yield1(int (*cb)(httpc_options_t *, const char *, httpc_callback, void *), httpc_options_t *a, const char *url, httpc_callback fn, void *param) {
	assert(cb);
	assert(a);
	assert(url);
	int r = HTTPC_YIELD;
	for (;r == HTTPC_YIELD;) {
		r = cb(a, url, fn, param);
		if (r == HTTPC_YIELD && a->flags & HTTPC_OPT_LOGGING_ON)
			(void)fprintf(stderr, "(yield)\n");
		if (httpc_sleep(a, 100) < 0) 
			r = HTTPC_ERROR;
	}
	return httpc_end_session(a) < 0 ? HTTPC_ERROR : r;
}

static int yield2(int (*cb)(httpc_options_t *, const char *), httpc_options_t *a, const char *url) {
	assert(cb);
	assert(a);
	assert(url);
	int r = HTTPC_YIELD;
	for (;r == HTTPC_YIELD;) {
		r = cb(a, url);
		if (r == HTTPC_YIELD && a->flags & HTTPC_OPT_LOGGING_ON)
			(void)fprintf(stderr, "(yield)\n");
		if (httpc_sleep(a, 100) < 0) 
			r = HTTPC_ERROR;
	}
	return httpc_end_session(a) < 0 ? HTTPC_ERROR : r;
}

int main(int argc, char **argv) {
	binary(stdin);
	binary(stdout);
	binary(stderr);

	httpc_options_t a = {
		.allocator  = httpc_allocator,
		.open       = httpc_open,
		.close      = httpc_close,
		.read       = httpc_read,
		.write      = httpc_write,
		.sleep      = httpc_sleep,
		.time       = httpc_time,
		.logger     = httpc_logger,
		.arena      = NULL,
		.socketopts = NULL,
		.logfile    = stderr,
	};

	int ch = 0, op = OP_GET, arg_custom_count = 0;
	char *arg_custom[argc];
	const char *url = NULL;
	httpc_getopt_t opt = { .init = 0, };
	while ((ch = httpc_getopt(&opt, argc, argv, "htu:o:1vykH:")) != -1) {
		switch (ch) {
		default: /* fall-through */
		case 'h': return help(stderr, argv[0]), 0;
		case 'o': op = operation(opt.arg); break;
		case 't': return -httpc_tests(&a);
		case 'u': url = opt.arg; break;
		case 'v': a.flags |= HTTPC_OPT_LOGGING_ON; break;
		case '1': a.flags |= HTTPC_OPT_HTTP_1_0; break;
		case 'y': a.flags |= HTTPC_OPT_NON_BLOCKING; break;
		case 'k': a.flags |= HTTPC_OPT_REUSE; break;
		case 'H': arg_custom[arg_custom_count++] = opt.arg; break;
		}
	}
	a.argc = arg_custom_count;
	a.argv = arg_custom;
	if (!url) {
		if (opt.index != (argc - 1)) {
			(void)help(stderr, argv[0]);
			return 1;
		}
		url = argv[opt.index++];
	}
	httpc_dump_t d = { .position = 0, .output = stdout, };
	switch (op) {
	case OP_GET:     return !!yield1(httpc_get,     &a, url, httpc_dump_cb, &d);
	case OP_HEAD:    return !!yield2(httpc_head,    &a, url);
	case OP_PUT:     return !!yield1(httpc_put,     &a, url, httpc_put_cb, stdin);
	case OP_DELETE:  return !!yield2(httpc_delete,  &a, url);
	case OP_POST:    return !!yield1(httpc_post,    &a, url, httpc_put_cb, stdin);
	case OP_TRACE:   return !!yield2(httpc_trace,   &a, url);
	case OP_OPTIONS: return !!yield2(httpc_options, &a, url);
	default:
		(void)fprintf(stderr, "operation unimplemented\n");
		return 1;
	}
	return 0;
}

