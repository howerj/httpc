VERSION=0x000002ul
# TODO -std=gnu99 should only be applied to 'unix.c', -std=c99 should be used elsewhere
CFLAGS=-Wall -Wextra -fPIC -std=gnu99 -O2 -pedantic -g -fwrapv ${DEFINES} ${EXTRA} -DHTTPC_VERSION="${VERSION}"
TARGET=httpc
AR      = ar
ARFLAGS = rcs
DESTDIR = install

# TODO: Try to make this portable instead?
ifeq ($(OS),Windows_NT)
DLL=dll
PLATFORM=win
LDLIBS= -lWs2_32
else # Assume Unixen
DLL=so
PLATFORM=unix
endif

.PHONY: all test clean dist install

all: ${TARGET}

test: ${TARGET}
	./${TARGET} -t

main.o: main.c ${TARGET}.h

${TARGET}.o: ${TARGET}.c ${TARGET}.h

${PLATFORM}.o: ${PLATFORM}.c ${TARGET}.h

lib${TARGET}.a: ${TARGET}.o ${PLATFORM}.o ${TARGET}.h
	${AR} ${ARFLAGS} $@ ${TARGET}.o ${PLATFORM}.o

lib${TARGET}.${DLL}: ${TARGET}.o ${TARGET}.h
	${CC} ${CFLAGS} -shared ${TARGET}.o ${PLATFORM}.o -o $@

${TARGET}: main.o lib${TARGET}.a

${TARGET}.1: readme.md
	-pandoc -s -f markdown -t man $< -o $@

install: ${TARGET} lib${TARGET}.a lib${TARGET}.${DLL} ${TARGET}.1
	install -p -D ${TARGET} ${DESTDIR}/bin/${TARGET}
	install -p -m 644 -D lib${TARGET}.a ${DESTDIR}/lib/lib${TARGET}.a
	install -p -D lib${TARGET}.${DLL} ${DESTDIR}/lib/lib${TARGET}.${DLL}
	install -p -m 644 -D ${TARGET}.h ${DESTDIR}/include/${TARGET}.h
	-install -p -m 644 -D ${TARGET}.1 ${DESTDIR}/man/${TARGET}.1
	mkdir -p ${DESTDIR}/src
	install -p -m 644 -D ${TARGET}.c ${TARGET}.h unix.c win.c main.c LICENSE readme.md makefile -t ${DESTDIR}/src
	install -p -D t ${DESTDIR}/src/t

dist: install
	tar zcf ${TARGET}-${VERSION}.tgz ${DESTDIR}

clean:
	git clean -dfx

