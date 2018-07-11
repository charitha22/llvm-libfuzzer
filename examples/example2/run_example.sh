

CXX=/home/min/a/cgusthin/codes/llvm-latest/build/bin/clang++
LIBS=-L/opt/gcc/7.1.0/lib64/ 
# Build test_fuzzer.cc with asan and link against libFuzzer.a
$CXX $LIBS -fsanitize=address -fsanitize-coverage=trace-pc-guard test_fuzzer.cc ../../libFuzzer.a
# Run the fuzzer with no corpus.
./a.out


