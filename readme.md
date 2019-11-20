# Embeddable HTTP(S) Client

* Project:    Embeddable HTTP(S) Client
* Author:     Richard James Howe
* Email:      <mailto:howe.r.j.89@gmail.com>
* License:    The Unlicense
* Repository: <https://github.com/howerj/httpc>

This library implements a small HTTP(S) client that can be used for downloading files 
and firmware on an embedded platform. The demonstration code targets [linux][] and 
[windows][] platforms.

The non-portable code for dealing with the [socket][] and [SSL/TLS][] layers must be
provided by the user and are not contained within the HTTPC library.
[SSL/TLS][] support is entirely optional.  The dependency on the C standard library 
is minimal and the allocator used by the HTTPC library can be provided by the 
user to aid in porting. The data is passed to a user supplied callback.

The library implements a retry mechanism and enough of [HTTP 1.1][] to allow
partially downloaded files to be resumed. This allows for a more reliable file
transfer over a bad network connection than [HTTP 1.0][] allows. A simple 
[HTTP 1.0][] client is almost trivial to implement, however it is not very
reliable.

There are other libraries that do something similar, however they tend to be
larger, more complex and more complete. [cURL][] is an example of one such
program and library - if you do decided to use it, good luck porting it!

# EXAMPLE USAGE

	Usage: ./httpc [-ht] *OR* -u URL *OR* URL

Options:

* **-h** : print out a help message to stderr and exit successfully.

* **-u** : specify the URL to attempt to download from

* **-t** : run the internal tests, returning zero on success, and none zero on failure

Examples:

	./httpc example.com/index.html
	./httpc http://example.com
	./httpc https://example.com


# C API

There are only a handful of functions required to be implemented in order to
port this client. If your platform has a [TCP/IP][] stack with a 
[Berkeley sockets][] like [API][] then porting should be trivial.

# BUILDING

To build you will need a [C99][] compiler and [GNU Make][].

To build:

	make

To run the internal tests:

	make test

To install:

	make install

The source code for the program is quite small, at the top of the 'httpc.c'
file there are a number of configurable options that can be specified by the
build system (and do not require you to modify the source itself).

The code is most likely to have been recently tested on Linux, it may work on
other Unixen, and it will be less frequently tested on Windows. Likewise, it is
more likely to have been tested on a 64-bit platform.

# RETURN CODES

This program will return a non-zero value on failure and zero on success. Like
pretty much every Unix program ever.

# BUGS

Known issues include:

* A line in the HTTP header must be smaller than 512 bytes in size (with the
  default configuration) otherwise parsing the header will fail.
* File sizes are probably limited up to 2GiB on many platforms.
* The project is currently in alpha, there are likely to be many problems and
  things not implemented.

For any bugs please contact the author at <mailto:howe.r.j.89@gmail.com>.
Please include as much information as possible including, but not limited to:
information on what platform you are compiling your code on (OS, 32/64-bit,
...), tracing information (for example, valgrind output), a minimal test 
case, thoughts, comments and general rants.

# LICENSE

This program is licensed under the [The Unlicense][], do what thou wilt.

# Goals

* [x] Get basic functionality sorted
* [ ] Handle partially downloaded files correctly
* [ ] Settle on an easy to use API which should allow reading/writing to
   be redirected to wherever the user wants.
* [ ] Make the library non-blocking, that is it should be able to resume
  if a open, close, read or write on a socket would block. This is more
  difficult that it first seems. Perhaps the line number could be used as
  a way of storing state...
* [ ] Try to remove any arbitrary limitations on the program
* [ ] Come up with a decent test suite, perhaps by using [netcat][].
  - Create a module that will allow the connection to be broken at
  arbitrary points.
  - Come up with a series of test files to be fed to netcat.
* [ ] Add a HTTPS version of the open/close functions
* This project could be extended to support other, small, Internet related
  protocols that are useful in an embedded context and are also simple to
  implement, such as [ntp][] and [dns][] clients.
* [ ] Be more liberal in what we accept to allow a slightly misbehaving server
  to still serve us files. This can be done by:
   - Allowing Unix line termination to be used instead of the proper line
     termination, but still accepting both.
   - By making all comparisons on text fields case insensitive (ASCII only).
* [ ] Perform optimizations on code
  - [ ] Reduce number of logging format strings
  - [ ] Allocate small buffers on the stack, then move to heap if needed
    amount becomes too big.
* [ ] Add more assertions
  - Pre and post conditions
  - Assert buffer indices within bounds
* [ ] Implement a subset of the [cURL][] command line options such
  as '-X', and more. Using a structure like this:

	struct options {
		int argc;
		char **argv; // extra fields in HTTP request headers
		char *command // GET/PUT/DELETE/...
	};

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
