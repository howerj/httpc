HTTPC_VERSION=4.1.2
STD=c99
CFLAGS=-Wall -Wextra -fPIC -std=${STD} -Os -g -pedantic -fwrapv ${DEFINES} ${EXTRA} -DHTTPC_VERSION="\"${HTTPC_VERSION}\""
TARGET=httpc
AR      = ar
ARFLAGS = rcs
DESTDIR = install
USE_SSL =1

ifeq ($(OS),Windows_NT)
EXE=.exe
DLL=dll
PLATFORM=win
LDLIBS= -lWs2_32
DLLIBS=
else # Assume Unixen
EXE=
DLL=so
PLATFORM=unix
DLLIBS=
endif

ifeq ($(USE_SSL),1)
LDLIBS += -lssl
ifeq ($(OS),Windows_NT)
DLLIBS += ${LDLIBS}
endif
endif

.PHONY: all test clean dist install

all: ${TARGET}

test: ${TARGET}
	./${TARGET} -t

main.o: main.c ${TARGET}.h makefile

${TARGET}.o: ${TARGET}.c ${TARGET}.h localely.h makefile

win.o:  win.c ${TARGET}.h makefile

unix.o: STD=gnu99
unix.o: unix.c ${TARGET}.h makefile

lib${TARGET}.a: ${TARGET}.o ${PLATFORM}.o ${TARGET}.h
	${AR} ${ARFLAGS} $@ ${TARGET}.o ${PLATFORM}.o

lib${TARGET}.${DLL}: ${TARGET}.o ${TARGET}.h
	${CC} ${CFLAGS} -shared ${TARGET}.o ${PLATFORM}.o ${DLLIBS} -o $@

${TARGET}: main.o lib${TARGET}.a
	${CC} ${CFLAGS} $^ ${LDLIBS} -o $@
	-strip $@${EXE}

${TARGET}.1: readme.md
	-pandoc -s -f markdown -t man $< -o $@

install: ${TARGET} lib${TARGET}.a lib${TARGET}.${DLL} ${TARGET}.1 .git
	install -p -D ${TARGET} ${DESTDIR}/bin/${TARGET}
	install -p -m 644 -D lib${TARGET}.a ${DESTDIR}/lib/lib${TARGET}.a
	install -p -m 755 -D lib${TARGET}.${DLL} ${DESTDIR}/lib/lib${TARGET}.${DLL}
	install -p -m 644 -D ${TARGET}.h ${DESTDIR}/include/${TARGET}.h
	-install -p -m 644 -D ${TARGET}.1 ${DESTDIR}/man/${TARGET}.1
	mkdir -p ${DESTDIR}/src
	cp -a .git ${DESTDIR}/src
	cd ${DESTDIR}/src && git reset --hard HEAD

dist: install
	tar zcf ${TARGET}-${VERSION}.tgz ${DESTDIR}

clean:
	git clean -dffx

