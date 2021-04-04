#!/bin/sh
bn=$(basename $1)
hexdump -v -e '8/1 "%02X ""\t"' -e '8/1 "%c""\n"' -n 10240 $1 >$bn.dump
