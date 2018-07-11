/home/min/a/cgusthin/codes/llvm-latest/build/bin/clang++ -g -std=c++11 -fsanitize=address -fsanitize-coverage=trace-pc-guard \
target.c -L/home/min/a/cgusthin/codes/llvm-latest/build/lib/clang/6.0.0/lib/linux \
-I/home/min/a/cgusthin/codes/llvm-latest/llvm/projects/compiler-rt/lib/fuzzer \
-o first_fuzzer
