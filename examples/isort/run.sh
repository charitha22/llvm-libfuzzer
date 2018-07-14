/home/min/a/cgusthin/codes/llvm-latest/build/bin/clang++ -g -std=c++11 -fsanitize=address -fsanitize-coverage=trace-pc-guard \
-L/opt/gcc/7.1.0/lib64/ \
isort_driver.cc ../../libFuzzer.a \
-o target
./target -max_len=20
