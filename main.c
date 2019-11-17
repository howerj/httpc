#include "httpc.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define UNUSED(X) ((void)(X))

typedef struct {
	size_t position;
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
static int httpc_dump(void *param, unsigned char *buf, size_t length, size_t position) {
	assert(param);
	assert(buf);
	httpc_dump_t *d = param;
	const size_t l = position + length;
	if (l < position)
		return HTTPC_ERROR;
	d->position = position + length;
	fwrite(buf, 1, length, stdout); 
	/* TODO: Keep track of position */
	return HTTPC_OK;
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
Usage:      %s -[ht] -u www.example.com/index.html\n\n\
Project:    Embeddable HTTP(S) Client\n\
Author:     Richard James Howe\n\
Email:      <mailto:howe.r.j.89@gmail.com>\n\
License:    The Unlicense\n\
Repository: <https://github.com/howerj/httpc>\n\
Version:    %d.%d.%d\n\
Flags:      %d\n\n\
Options:\n\n\
\t-h\tprint help and exit\n\
\t-t\trun the built in tests, returning failure status\n\
\t-u URL\tset URL to use\n\
\tURL\tset URL to use\n\
\n\
Returns non zero value on failure.\n\n";
	return fprintf(out, fmt, arg0, x, y, z, q);
}

int main(int argc, char **argv) {
	httpc_os_t a = {
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

	int ch = 0;
	const char *url = NULL;
	httpc_getopt_t opt = { .init = 0 };
	while ((ch = httpc_getopt(&opt, argc, argv, "htu:")) != -1) {
		switch (ch) {
		case 'h': return help(stderr, argv[0]), 0;
		case 't': return -httpc_tests(&a);
		case 'u': url = opt.arg; break;
		}
	}
	if (!url) {
		if (opt.index != (argc - 1)) {
			(void)help(stderr, argv[0]);
			return 1;
		}
		url = argv[opt.index++];
	}
	httpc_dump_t d = { .position = 0 };
	if (httpc_get(url, &a, httpc_dump, &d) != HTTPC_OK)
		return 1;
	return 0;
}

