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
	enum { BADARG_E = ':', BADCH_E = '?' };

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

/* NOTE: The way the callback mechanism works, the callback has to keep track
 * of the position, we should probably do that in the library instead,
 * discarding everything until we get back to where we are. Also bear in mind
 * even if "position < d->position", "position + length" could be greater than
 * "d->position". */
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
	unsigned long version = 0;
	const int r = httpc_version(&version);
	if (r < 0)
		(void)fprintf(stderr, "build incorrectly - unset version number");
	const int q = (version >> 24) & 0xFFu;
	const int x = (version >> 16) & 0xFFu;
	const int y = (version >>  8) & 0xFFu;
	const int z = (version >>  0) & 0xFFu;
	const char *fmt = "\
Usage:      %s -[ht1v] -u www.example.com/index.html\n\n\
Project:    Embeddable HTTP(S) Client\n\
Author:     Richard James Howe\n\
Email:      <mailto:howe.r.j.89@gmail.com>\n\
License:    The Unlicense\n\
Repository: <https://github.com/howerj/httpc>\n\
Version:    %d.%d.%d\n\
Flags:      %d\n\n\
Options:\n\n\
\t-o #\tset operation GET/HEAD/PUT/DELETE\n\
\t-h\tprint help and exit\n\
\t-t\trun the built in tests, returning failure status\n\
\t-u URL\tset URL to use\n\
\t-1 perform HTTP 1.0 request, not a HTTP 1.1 request\n\
\t-v turn logging on\n\
\tURL\tset URL to use\n\
\n\
Returns non zero value on failure. stdin(3) for input, stdout(3)\n\
for output, and stderr(3) for logging\n\n";
	return fprintf(out, fmt, arg0, x, y, z, q);
}

enum { OP_GET, OP_HEAD, OP_PUT, OP_POST, OP_DELETE };

static int operation(const char *s) {
	assert(s);
	if (!strcmp(s, "GET"))
		return OP_GET;
	if (!strcmp(s, "HEAD"))
		return OP_HEAD;
	if (!strcmp(s, "PUT"))
		return OP_PUT;
	if (!strcmp(s, "POST"))
		return OP_POST;
	if (!strcmp(s, "DELETE"))
		return OP_DELETE;
	return -1;
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
		.logger     = httpc_logger,
		.arena      = NULL,
		.socketopts = NULL,
		.logfile    = stderr,
	};

	int ch = 0, op = OP_GET;
	const char *url = NULL;
	httpc_getopt_t opt = { .init = 0 };
	while ((ch = httpc_getopt(&opt, argc, argv, "htu:o:1v")) != -1) {
		switch (ch) {
		case 'o': op = operation(opt.arg); break;
		case 'h': return help(stderr, argv[0]), 0;
		case 't': return -httpc_tests(&a);
		case 'u': url = opt.arg; break;
		case 'v': a.flags |= HTTPC_OPT_LOGGING_ON; break;
		case '1': a.flags |= HTTPC_OPT_HTTP_1_0; break;
		}
	}
	if (!url) {
		if (opt.index != (argc - 1)) {
			(void)help(stderr, argv[0]);
			return 1;
		}
		url = argv[opt.index++];
	}
	httpc_dump_t d = { .position = 0, .output = stdout };
	switch (op) {
	case OP_GET:    return httpc_get(&a, url, httpc_dump_cb, &d) != HTTPC_OK ? 1 : 0;
	case OP_HEAD:   return httpc_head(&a, url) != HTTPC_OK ? 1 : 0;
	case OP_PUT:    return httpc_put(&a, url, httpc_put_cb, stdin) != HTTPC_OK ? 1 : 0;
	case OP_DELETE: return httpc_delete(&a, url) != HTTPC_OK ? 1 : 0;
	case OP_POST:
	default:
		fprintf(stderr, "operation unimplemented\n");
		return 1;
	}
	return 0;
}

