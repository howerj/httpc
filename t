#!/bin/bash
#
# HTTPC: HTTP Client Test Suite
# Tests go here!
#
# NB. If cURL is installed we could use that to compare 
# downloaded files from various sources.
#

NC=nc
LOCAL=127.0.0.1

set -x
set -e
set -u
make httpc
./httpc -t

EX1=$(cat <<'EOF'
HTTP/1.1 200 OK 
Content-Type: text/plain 
Transfer-Encoding: chunked

7
Mozilla
9
Developer
7
Network
4
Wiki
5
pedia
E
 in

chunks.
0
EOF 
)

EX2=$(cat <<'EOF'
HTTP/1.1 301 Moved Permanently
Location: 127.0.0.1:8080

EOF
);

echo "${EX1}" | unix2dos | ${NC} -l -p 8080 &
p1=$!
echo "${EX2}" | unix2dos | "${NC}" -l -p 8081 &
p2=$!

./httpc "${LOCAL}:8081"

kill -9 ${p1} || true;
kill -9 ${p2} || true;

exit 0
