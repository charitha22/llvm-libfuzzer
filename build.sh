#!/bin/bash
LIBFUZZER_SRC_DIR=$(dirname $0)
#CXX=/home/min/a/cgusthin/codes/llvm-latest/build/bin/clang
CXX=gcc
for f in $LIBFUZZER_SRC_DIR/*.cpp; do
  $CXX -g -O2 -fno-omit-frame-pointer  -std=c++11 $f -c &
done
wait
rm -f libFuzzer.a
ar ru libFuzzer.a Fuzzer*.o
rm -f Fuzzer*.o

