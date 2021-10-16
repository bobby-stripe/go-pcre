#!/bin/bash
set -euo pipefail

echo 'package pcre' >constants.go
echo '' >>constants.go
echo 'const (' >>constants.go

cat pcre2.h | egrep '#define PCRE2_.*\s(\(?\-?\d+\)?(\s|$)|0x)' | perl -pe 's/u(\s|$)/$1/' | perl -pe 's/#define PCRE2_/\t/' | perl -pe 's/(\s*\w+)/$1 =/' | grep -v LOCAL_WIDTH >>constants.go; echo ')' >>constants.go

go fmt
