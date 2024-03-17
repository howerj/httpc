% HTTPC(1) | A HTTP(S) Client For The Discerning Embedded Programmer

# NAME

HTTPC - A HTTP(S) Client For The Discerning Embedded Programmer

# SYNOPSIS

httpc -t

httpc example.com

httpc -o PUT example.com < file.txt

# DESCRIPTION

	Project:    Embeddable HTTP(S) Client
	Author:     Richard James Howe
	Email:      <mailto:howe.r.j.89@gmail.com>
	License:    The Unlicense
	Repository: <https://github.com/howerj/httpc>

This library implements a small HTTP(S) client that can be used for downloading files
and firmware on an embedded platform. The demonstration code targets [linux][] and
[windows][] platforms.

The non-portable code for dealing with the [socket][] and [SSL/TLS][] layers must be
provided by the user and are not contained within the HTTPC library.
[SSL/TLS][] support is entirely optional.  The dependency on the C standard library
is minimal (mostly string functions) and the allocator used by the HTTPC library
can be provided by the user to aid in porting. The data is passed to a user supplied
callback.

The library implements a retry mechanism and enough of [HTTP 1.1][] to allow
partially downloaded files to be resumed. This allows for a more reliable file
transfer over a bad network connection than [HTTP 1.0][] allows. A simple
[HTTP 1.0][] client is almost trivial to implement, however it is not very
reliable. Only certain operations are retried in full with a resume
("GET"/"HEAD"), others are not retried if a negative response is received
("DELETE"/"POST"/"POST").

There are other libraries that do something similar, however they tend to be
larger, more complex and more complete. [cURL][] is an example of one such
program and library - if you do decided to use it, good luck porting it!

Use cases:

* Downloading firmware over an unreliable connection.
* Poking a web-server with data.
* Talking to a known, trusted server.

# EXAMPLE USAGE

	Usage: ./httpc [-ht] *OR* -[1vy] -u URL *OR* -[1vy] URL

Options:

* **-h** : print out a help message to stderr and exit successfully.

* **-u** : specify the URL to attempt to download from

* **-t** : run the internal tests, returning zero on success, and none zero on failure

* **-1** : perform a HTTP 1.0 request, with HTTP 1.1 responses still being dealt with

* **-v** : add logging

* **-y** : turn yielding on, this is only useful for debugging the library.

* **-H**: add a custom header to the request

Examples:

	./httpc example.com/index.html
	./httpc http://example.com
	./httpc https://example.com


# C API

There are only a handful of functions required to be implemented in order to
port this client. If your platform has a [TCP/IP][] stack with a
[Berkeley sockets][] like [API][] then porting should be trivial.

The functions all return negative on failure, zero on successful completion of
an operation or session, and there are some positive values that are used to to
signal special cases (such as the HTTP client yielding to the caller,
"HTTPC\_YIELD"), or the operation is finished but the connection is open
("HTTPC\_REUSE" is returned). Both of these special return values are not
encountered unless enabled, which by default they are not.

For each connection a "httpc\_options\_t" structure must be readied, which will
contain the callbacks needed to connect to the web-server, and to allocate
memory. Very little memory is allocated, non-blocking memory operations use
allocate more on the heap, but blocking operations use more stack space.
Allocation is only done during session setup usually, and should not grow
during normal operation.

The following functions support non-blocking modes of operation, and reusing
the HTTP connection after successful requests (unsuccessful requests cause the
connection to be closed, and reopened, as do redirects).

	int httpc_get(httpc_options_t *a, const char *url, httpc_callback fn, void *param);
	int httpc_put(httpc_options_t *a, const char *url, httpc_callback fn, void *param);
	int httpc_post(httpc_options_t *a, const char *url, httpc_callback fn, void *param);
	int httpc_head(httpc_options_t *a, const char *url);
	int httpc_delete(httpc_options_t *a, const char *url);
	int httpc_trace(httpc_options_t *a, const char *url);
	int httpc_options(httpc_options_t *a, const char *url);

The callback for the GET operation is called only when receiving the response
body. Likewise the callback for the PUT operation is only called when sending
the request body. All operations can optionally have both requests and response
bodies according to the specification, but there is no way to deal with both
(to keep things simple).

"httpc\_head", "httpc\_trace", and "httpc\_options" are really
only useful for interactive debugging purposes when logging is turned on. It is
expected that they will not be used on an embedded platform.

These functions support blocking operations only, and do not support reusing
the connection:

	int httpc_get_buffer(httpc_options_t *a, const char *url, char *buffer, size_t *length);
	int httpc_put_buffer(httpc_options_t *a, const char *url, char *buffer, size_t length);
	int httpc_post_buffer(httpc_options_t *a, const char *url, char *buffer, size_t length);

The above functions are for reading into a buffer (GET) writing from a buffer
(PUT, POST). GET expects the length of the buffer to be passed into 'length',
and it returns the actual length of the data retrieved in 'length'. If the
buffer is not big enough an error is returned.

The "httpc\_tests" function executes a series of built in unit tests, they may
be compiled out with the right define to save on space.

	int httpc_tests(httpc_options_t *a);

You should not normally need to run this function. Negative is returned on
error, as usual.

The function "httpc\_end\_session";

	int httpc_end_session(httpc_options_t *a);

Is only needed when using the yield option and you want to end a HTTP operation
prematurely, or when using the keep-alive options and you want to finally close
the connection. It is safe to call this function multiple times, or if those
options are not set.

# BUILDING

To build you will need a [C99][] compiler and [GNU Make][]. There are minimal
system dependencies on the C standard library, the other dependencies needed
are for the [SSL/TLS][] library used which can be compiled out, and the systems
[TCP/IP][] stack.

To build:

	make

To build without [SSL/TLS][] support:

	make DEFINES="-DUSE_SSL=0"

To run the internal tests:

	make test

To install:

	make install

The source code for the program is quite small, at the top of the 'httpc.c'
file there are a number of configurable options that can be specified by the
build system (and do not require you to modify the source itself).

The code is most likely to have been recently tested on Linux, it may work on
other Unixen, and it will be less frequently tested on Windows. Likewise, it is
more likely to have been tested on a 64-bit platform. The SSL library, if used
at all, should provide an openSSL interface on either Windows or Linux.

# RETURN CODES

This program will return a non-zero value on failure and zero on success. Like
pretty much every Unix program ever.

# LICENSE

This program is licensed under the [The Unlicense][], do what thou wilt.

# LIMITATIONS

Known limitations include:

* If reallocation is disabled (is is enabled by default) then the default
  buffer size (of 128, which can be changed) will place limitations of URL
  length and line length (each field in the HTTP header is a single line).
* File sizes are probably limited up to 2GiB on many platforms.
* The library has a non-blocking mechanism, however what this really means is
  'less-blocky' and may block until a time out on a socket. This is likely to
  improve and yield more often as time goes on. However turning this library
  into a fully non-blocking version is a non-trivial task. See
  <https://www.chiark.greenend.org.uk/~sgtatham/coroutines.html> for both
  a description of the problem and a possible solution in C.
* The library should be fuzzed, and has not been. Preferably with something
  like [AFL](https://lcamtuf.coredump.cx/afl/).
* The library would be better expressed as a 
  [header only library](https://en.wikipedia.org/wiki/Header-only) as that
  is what all of the cool kids are using.
* The library is quite thirsty for stack size for a library meant to be run on
  an embedded microcontroller. It will require at least 1KiB of stack, and
  possibly more depending on how your callbacks are written.
* The client is more liberal in what it will accept from the server than it
  should be, allowing newlines to be terminated by a single CR with no LF, and
  comparisons are done in a case-insensitive manner.
* HTTP Status Code 206 (partial content) is not handled, which could be fairly
  easily.
* A C++ wrapper, and wrappers for other language, would not go amiss.
* The socket and SSL settings are provided by a series of callbacks - this
  allows you to set things like timeouts and keep-alive settings, the defaults
  may not suite you.
* The set of functions provided by this library should suite the common cases,
  however somethings are not supported, for example a GET request can have a
  body.
* Entropy cannot be reversed, meaning all acts of man no matter how great will
  eventually be rendered futile, the best one can hope for is eternal return,
  are you proud of what you have achieved? Or will you die like a dog in the
  face of heat-death?
* This library does not implement [WebSockets][], but looking through the
  specification, they should be fairly easy to implement.

# BUGS

For any bugs please contact the author at <mailto:howe.r.j.89@gmail.com>.
Please include as much information as possible including, but not limited to:
information on what platform you are compiling your code on (OS, 32/64-bit,
...), tracing information (for example, valgrind output), a minimal test
case, a (small) blood sacrifice, three bushels of wheat, thoughts, comments 
and general rants. Alternatively shout into a buck or pray to your gods.

[WebSockets]: https://en.wikipedia.org/wiki/WebSocket
[linux]: https://www.linux.org/
[windows]: https://www.microsoft.com/en-gb/windows
[socket]: https://en.wikipedia.org/wiki/Network_socket
[SSL/TLS]: https://en.wikipedia.org/wiki/Transport_Layer_Security
[GNU Make]: https://www.gnu.org/software/make/
[C99]: https://en.wikipedia.org/wiki/C99
[gcc]: https://gcc.gnu.org/
[The Unlicense]: https://unlicense.org/
[HTTP 1.1]: https://www.w3.org/Protocols/rfc2616/rfc2616.html
[HTTP 1.0]: https://www.w3.org/Protocols/HTTP/1.0/spec.html
[Berkeley sockets]: https://en.wikipedia.org/wiki/Berkeley_sockets
[TCP/IP]: https://en.wikipedia.org/wiki/Internet_protocol_suite
[API]: https://en.wikipedia.org/wiki/Application_programming_interface
[cURL]: https://curl.haxx.se/
[netcat]: https://en.wikipedia.org/wiki/Netcat
[ntp]: https://en.wikipedia.org/wiki/Network_Time_Protocol
[dns]: https://en.wikipedia.org/wiki/Domain_Name_System
