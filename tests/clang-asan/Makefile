CXX=/home/min/a/cgusthin/codes/llvm-latest/build/bin/clang++
all:
	$(CXX) -g  -fsanitize-coverage=edge,no-prune,trace-pc-guard,inline-8bit-counters trace-pc-guard-example.cc -c 
	$(CXX)  trace-pc-guard-cb.cc trace-pc-guard-example.o -fsanitize=address
	ASAN_OPTIONS=strip_path_prefix=`pwd`/ ./a.out
clean:
	rm -f *.o a.out
