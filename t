#!/bin/sh
#
# HTTPC: HTTP Client Test Suite
# Tests go here!
#

NC=nc
LOCAL=127.0.0.1

set -x
set -e
set -u
make httpc
./httpc -t

${NC} -l -p 8080 < ex1.txt &
p1=$!
${NC} -l -p 8081 < ex2.txt &
p2=$!

./httpc "${LOCAL}:8081"

kill -9 ${p1} || true;
kill -9 ${p2} || true;

exit 0
